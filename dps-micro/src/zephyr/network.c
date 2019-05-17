/**
 * @file
 * Network layer macros and functions
 */

/*
 *******************************************************************
 *
 * Copyright 2019 Intel Corporation All rights reserved.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr.h>
#include <errno.h>
#include <fcntl.h>

#include <misc/byteorder.h>
#include <misc/util.h>
#include <misc/fdtable.h>
#include <net/socket.h>
#include <net/tls_credentials.h>
#include <net/udp.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>


#include <dps/dps.h>
#include <dps/err.h>
#include <dps/dbg.h>
#include <dps/private/node.h>
#include <dps/private/coap.h>
#include <dps/private/network.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define RX_BUFFER_SIZE 2048

#define IPV4  0
#define IPV6  1

struct _DPS_NodeAddress {
    struct sockaddr_storage inaddr;
};

typedef enum {
    DTLS_DISABLED,
    DTLS_ENABLED,
    DTLS_IS_CLIENT,
    DTLS_IS_SERVER
} DTLS_State;

struct _DPS_Network {
    DTLS_State dtlsState;
#ifdef DPS_IPV4
    int ucast4;       /* IPv4 unicast socket */
    int mcast4;       /* IPv4 multicast socket */
#endif
    int ucast6;       /* IPv6 unicast socket */
    int mcast6;       /* IPv6 multicast socket */
    uint8_t rxBuffer[RX_BUFFER_SIZE];
    size_t txLen;
    struct sockaddr_in addrCOAP4;
    struct sockaddr_in6 addrCOAP6;
    DPS_NodeAddress remoteNode;
    DPS_SendComplete sendCB;
    void* appData;
};

static DPS_Network netContext;

/*
 * Variables for the I/O completion callback thread
 */
static k_tid_t threadId;
static struct k_thread threadData;

#define THREAD_PRIORITY       5
#define THREAD_STACK_SIZE  2048

K_THREAD_STACK_DEFINE(threadStack, THREAD_STACK_SIZE);

#define DPS_TAG         0
#define DPS_SERVER_CERT_TAG     1
#define DPS_PRIVATE_KEY_TAG     2
#define DPS_PSK_TAG             3

static const sec_tag_t sec_tag_list[] = {
    DPS_TAG,
    DPS_SERVER_CERT_TAG,
    DPS_PRIVATE_KEY_TAG,
    DPS_PSK_TAG
};

/*
 * Used when the key store supports certificates.
 */
static const int AllCipherSuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
    0
};

/*
 * Used when the key store supports only PSKs.
 */
static const int PskCipherSuites[] = {
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
    0
};

static DPS_Status ConfigureDTLS(DPS_Node* node, int sock, DTLS_State role);

const char* DPS_AddrToText(const DPS_NodeAddress* addr)
{
    static char txt[INET6_ADDRSTRLEN];

    if (addr->inaddr.ss_family == AF_INET) {
        struct sockaddr_in* sa4 = (struct sockaddr_in*)&addr->inaddr;
        return net_addr_ntop(AF_INET, &sa4->sin_addr, txt, sizeof(txt));
    } else {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)&addr->inaddr;
        return net_addr_ntop(AF_INET6, &sa6->sin6_addr, txt, sizeof(txt));
    }
}

const DPS_NodeAddress* DPS_TextToAddr(const char* addrStr, uint16_t port)
{
    static DPS_NodeAddress addr;
    int family = AF_INET;
    int ret;

    if (addrStr) {
        const char* p = addrStr;
        while (*p) {
            if (*p++ == ':') {
                family = AF_INET6;
                break;
            }
        }
    } else {
        family = AF_INET6;
        addrStr = "::1";
    }

    memset(&addr, 0, sizeof(DPS_NodeAddress));

    if (family == AF_INET) {
        struct sockaddr_in* sa4 = (struct sockaddr_in*)&addr.inaddr;
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons(port);
        ret = net_addr_pton(family, addrStr, &sa4->sin_addr);
    } else {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)&addr.inaddr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        ret = net_addr_pton(family, addrStr, &sa6->sin6_addr);
    }
    if (ret <= 0) {
        if (ret < 1) {
            DPS_ERRPRINT("InetPton returned %d\n", errno);
        }
        return NULL;
    } else {
        return &addr;
    }
}

void DPS_NodeAddressSetPort(DPS_NodeAddress* addr, uint16_t port)
{
    port = htons(port);
    if (addr->inaddr.ss_family == AF_INET6) {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)&addr->inaddr;
        sa6->sin6_port = port;
    } else {
        struct sockaddr_in* sa4 = (struct sockaddr_in*)&addr->inaddr;
        sa4->sin_port = port;
    }
}

DPS_NodeAddress* DPS_AllocNodeAddress()
{
    return DPS_Calloc(sizeof(DPS_NodeAddress), DPS_ALLOC_LONG_TERM);
}

void DPS_FreeNodeAddress(DPS_NodeAddress* addr)
{
    DPS_Free(addr, DPS_ALLOC_LONG_TERM);
}

void DPS_CopyNodeAddress(DPS_NodeAddress* dest, const DPS_NodeAddress* src)
{
    memcpy(dest, src, sizeof(DPS_NodeAddress));
}


int DPS_SameNodeAddress(const DPS_NodeAddress* addr1, const DPS_NodeAddress* addr2)
{
    static const uint8_t IP4as6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };
    const struct sockaddr* a = (const struct sockaddr*)&addr1->inaddr;
    const struct sockaddr* b = (const struct sockaddr*)&addr2->inaddr;
    struct sockaddr_in6 tmp;

    if (a->sa_family != b->sa_family) {
        uint32_t ip;
        tmp.sin6_family = AF_INET6;
        if (a->sa_family == AF_INET6) {
            const struct sockaddr_in* ipb = (const struct sockaddr_in*)b;
            tmp.sin6_port = ipb->sin_port;
            ip = ipb->sin_addr.s_addr;
        } else {
            const struct sockaddr_in* ipa = (const struct sockaddr_in*)a;
            tmp.sin6_port = ipa->sin_port;
            ip = ipa->sin_addr.s_addr;
        }
        memcpy(&tmp.sin6_addr, IP4as6, 12);
        memcpy((uint8_t*)&tmp.sin6_addr + 12, &ip, 4);
        if (a->sa_family == AF_INET6) {
            b = (const struct sockaddr*)&tmp;
        } else {
            a = (const struct sockaddr*)&tmp;
        }
    }
    if (a->sa_family == AF_INET6 && b->sa_family == AF_INET6) {
        const struct sockaddr_in6* ip6a = (const struct sockaddr_in6*)a;
        const struct sockaddr_in6* ip6b = (const struct sockaddr_in6*)b;
        return (ip6a->sin6_port == ip6b->sin6_port) && (memcmp(&ip6a->sin6_addr, &ip6b->sin6_addr, 16) == 0);
    } else if (a->sa_family == AF_INET && b->sa_family == AF_INET) {
        const struct sockaddr_in* ipa = (const struct sockaddr_in*)a;
        const struct sockaddr_in* ipb = (const struct sockaddr_in*)b;
        return (ipa->sin_port == ipb->sin_port) && (ipa->sin_addr.s_addr == ipb->sin_addr.s_addr);
    } else {
        return DPS_FALSE;
    }
}

DPS_Status DPS_NetworkInit(DPS_Node* node)
{
    DPS_Status status = DPS_OK;

    DPS_DBGTRACE();

    /* Initialize the Ethernet driver on the default interface */
    ethernet_init(net_if_get_default());

    memset(&netContext, 0, sizeof(netContext));
    node->network = &netContext;
    node->remoteNode = &netContext.remoteNode;

    /* By default DTLS is enabled */
    node->network->dtlsState = DTLS_ENABLED;

    return status;
}

void DPS_NetworkTerminate(DPS_Node* node)
{
    node->network = NULL;
}

DPS_Status DPS_DisableDTLS(DPS_Node* node)
{
    DPS_Network* net = node->network;

    if (net->dtlsState == DTLS_ENABLED) {
        net->dtlsState = DTLS_DISABLED;
        return DPS_OK;
    } else {
        DPS_ERRPRINT("Cannot disable DTLS after a session has started\n");
        return DPS_ERR_INVALID;
    }
}

/* Local address - TODO should be randomly assiged or a configuration parameter */
#define LOCAL_ADDR_6   "2001:db8::1"
#define LOCAL_ADDR_4   "169.254.78.133"

static DPS_Status MCastInit(DPS_Network* net)
{
    int ret;
	struct in6_addr addr6;
    struct sockaddr_in6 mcast6;
	struct net_if_addr* ifaddr;
    struct net_if_mcast_addr* mcast;
	struct net_if* iface;

    DPS_DBGTRACE();

    /*
     * Join the multicast group
     */
    ret = net_addr_pton(AF_INET6, LOCAL_ADDR_6, &addr6);
    if (ret) {
		DPS_DBGPRINT("Invalid IPv6 address\n");
		return DPS_ERR_NETWORK;
    }
    memset(&mcast6, 0, sizeof(mcast6));
    ret = net_addr_pton(AF_INET6, COAP_MCAST_ALL_NODES_LINK_LOCAL_6, &mcast6.sin6_addr);
    if (ret) {
		DPS_DBGPRINT("Invalid IPv6 multicast address\n");
		return DPS_ERR_NETWORK;
    }

	iface = net_if_get_default();
	if (!iface) {
		DPS_DBGPRINT("Could not get the default interface\n");
		return DPS_ERR_NETWORK;
	}

    /* Need to set a unicast address on the interface */
	ifaddr = net_if_ipv6_addr_add(iface, &addr6, NET_ADDR_MANUAL, 0);
	if (!ifaddr) {
		DPS_DBGPRINT("Could not add unicast address to interface\n");
		return DPS_ERR_NETWORK;
	}
	ifaddr->addr_state = NET_ADDR_PREFERRED;
    /* Now we can add the multicast address */
	mcast = net_if_ipv6_maddr_add(iface, &mcast6.sin6_addr);
	if (!mcast) {
		DPS_DBGPRINT("Could not add multicast address to interface\n");
		return DPS_ERR_NETWORK;
	}
    /* Bind the multicast addressess and port */
    net->mcast6 = zsock_socket(AF_INET6, SOCK_DGRAM, 0);
    zsock_fcntl(net->mcast6, F_SETFL, O_NONBLOCK);
    mcast6.sin6_family = AF_INET6;
    mcast6.sin6_port = htons(COAP_UDP_PORT);
    ret = zsock_bind(net->mcast6, (struct sockaddr*)&mcast6, sizeof(mcast6));
    if (ret) {
		DPS_DBGPRINT("Unable to bind IPv6 multicast address %d\n", ret);
		return DPS_ERR_NETWORK;
    }
	return DPS_OK;
}

/* TODO - currently there is no Zephyr API to get the port number */
static uint16_t GetPort(int sock)
{
    struct net_context* ctx = z_get_fd_obj(sock, NULL, 0);
    uint16_t port;

    if (ctx) {
        if (ctx->local.family == AF_INET6) {
            const struct sockaddr_in6_ptr* addr = net_sin6_ptr(&ctx->local);
            port = addr->sin6_port;
        } else {
            const struct sockaddr_in_ptr* addr = net_sin_ptr(&ctx->local);
            port = addr->sin_port;
        }
        return ntohs(port);
    } else {
        DPS_ERRPRINT("Unable to get net context for socket\n");
        return 0;
    }
}

#define NUM_FDS  2

static void CallbackThread(void* arg1, void* arg2, void* arg3)
{
    DPS_Node* node = (DPS_Node*)arg1;
    DPS_Network* net = (DPS_Network*)arg2;
    DPS_OnReceive onRecvCB = arg3;
    struct zsock_pollfd fds[NUM_FDS];
    DPS_RxBuffer rxBuf;

    fds[0].fd =  net->mcast6;
    fds[0].events = ZSOCK_POLLIN | ZSOCK_POLLOUT;
    fds[1].fd =  net->ucast6;
    fds[1].events = ZSOCK_POLLIN | ZSOCK_POLLOUT;

    while (1) {
        int ret = zsock_poll(fds, NUM_FDS, -1);
        if (ret > 0) {
            int i;
            for (i = 0; i < NUM_FDS; ++i) {
                if (fds[i].revents & ZSOCK_POLLIN) {
                    DPS_Status status = DPS_OK;
                    DPS_NodeAddress from;
                    ssize_t sz;
                    int multicast = (fds[i].fd == net->mcast6);
                    socklen_t addrLen = sizeof(DPS_NodeAddress);

                    if (!multicast && net->dtlsState == DTLS_ENABLED) {
                        status = ConfigureDTLS(node, net->ucast6, DTLS_IS_SERVER);
                    }
                    sz = zsock_recvfrom(fds[i].fd, net->rxBuffer, RX_BUFFER_SIZE, 0, (struct sockaddr*)&from, &addrLen);
                    if (sz < 0) {
                        DPS_ERRPRINT("recvFrom returned errno %d\n", errno);
                        continue;
                    }
                    DPS_RxBufferInit(&rxBuf, net->rxBuffer, sz);
                    if (sz == 0) {
                        status = DPS_ERR_EOF;
                    }
                    onRecvCB(node, &from, multicast, &rxBuf, status);
                }
                if (fds[i].revents & ZSOCK_POLLOUT) {
                    DPS_SendComplete sendCB = net->sendCB;
                    net->sendCB = NULL;
                    if (sendCB) {
                        sendCB(node, net->appData, DPS_OK);
                    }

                }
            }
        }
    }

}

static DPS_Status CAChainResponse(const char* ca, void* data)
{
    size_t len = ca ? strlen(ca) + 1 : 0;

    DPS_DBGTRACE();

    if (len) {
        int ret = tls_credential_add(DPS_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, ca, len);
        if (ret == 0) {
            return DPS_OK;
        }
        DPS_WARNPRINT("Failed to add cert chain\n");
    }
    return DPS_ERR_MISSING;
}

static DPS_Status CertResponse(const DPS_Key* key, const DPS_KeyId* keyId, void* data)
{
    int ret;

    DPS_DBGTRACE();

    if (key->type != DPS_KEY_EC_CERT || !key->cert.cert || !key->cert.privateKey) {
        return DPS_ERR_MISSING;
    }

    ret = tls_credential_add(DPS_TAG, TLS_CREDENTIAL_SERVER_CERTIFICATE, key->cert.cert, strlen(key->cert.cert) + 1);
    if (ret != 0) {
        DPS_WARNPRINT("Failed to add server cert\n");
        return DPS_ERR_MISSING;
    }

    if (key->cert.password && *key->cert.password) {
        DPS_ERRPRINT("Zephr API doesn't support password protected private keys\n");
        return DPS_ERR_MISSING;
    }

    ret = tls_credential_add(DPS_TAG, TLS_CREDENTIAL_PRIVATE_KEY, key->cert.privateKey, strlen(key->cert.privateKey) + 1);
    if (ret != 0) {
        DPS_WARNPRINT("Failed to add private key\n");
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static DPS_Status KeyResponse(const DPS_Key* key, const DPS_KeyId* keyId, void* data)
{
    int ret;

    DPS_DBGTRACE();

    ret = tls_credential_add(DPS_TAG, TLS_CREDENTIAL_PSK, key->symmetric.key, key->symmetric.len);
    if (ret != 0) {
        DPS_WARNPRINT("Failed to add PSK\n");
        return DPS_ERR_MISSING;
    }
    ret = tls_credential_add(DPS_TAG, TLS_CREDENTIAL_PSK_ID, keyId->id, keyId->len);
    if (ret != 0) {
        DPS_WARNPRINT("Failed to add PSK Id\n");
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static DPS_Status ConfigureDTLS(DPS_Node* node, int sock, DTLS_State role)
{
    DPS_KeyStore* keyStore = node->keyStore;
    int ret;
    DPS_Status status = DPS_OK;

    DPS_DBGTRACE();

    if (!keyStore) {
        return DPS_ERR_NULL;
    }
    node->network->dtlsState = role;

    /*
     * Specify if we are configuring a DTLS client or server
     */
	ret = zsock_setsockopt(sock, SOL_TLS, TLS_DTLS_ROLE, &role, sizeof(int));
	if (ret != 0) {
		DPS_ERRPRINT("Failed to set TLS_DTLS_ROLE option: %d", errno);
        return DPS_ERR_NETWORK;
	}
    /*
     * Disable host name checking
     */
	ret = zsock_setsockopt(sock, SOL_TLS, TLS_HOSTNAME, NULL, 0);
	if (ret != 0) {
		DPS_ERRPRINT("Failed to set TLS_HOSTNAME option: %d", errno);
        return DPS_ERR_NETWORK;
	}

    /*
     * This sets the tag vocabulary for this socket
     */
	ret = zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list, sizeof(sec_tag_list));
	if (ret != 0) {
		DPS_ERRPRINT("Failed to set TLS_SEC_TAG_LIST option: %d", errno);
        return DPS_ERR_NETWORK;
	}

    /* Check if we are able to configure cert based authentication or just pre-shared keys */
    if (keyStore->caChainRequest && keyStore->keyRequest) {
        status = keyStore->caChainRequest(keyStore, CAChainResponse, node);
        if (status == DPS_OK) {
            ret = keyStore->keyRequest(keyStore, &node->signer.kid, CertResponse, node);
        }
        if (status == DPS_OK) {
            ret = zsock_setsockopt(sock, SOL_TLS, TLS_CIPHERSUITE_LIST, AllCipherSuites, sizeof(AllCipherSuites));
        } else {
            ret = zsock_setsockopt(sock, SOL_TLS, TLS_CIPHERSUITE_LIST, PskCipherSuites, sizeof(PskCipherSuites));
        }
        if (ret != 0) {
            DPS_ERRPRINT("Failed to set TLS_CIPHERSUITE_LIST option: %d", errno);
            return DPS_ERR_NETWORK;
        }
    }
    /*
     * TODO - Zephyr doesn't have API support for handling server PSK callbacks so
     * all we can do is register the same PSK for all clients.
     */
    if (keyStore->keyAndIdRequest) {
        status = keyStore->keyAndIdRequest(keyStore, KeyResponse, node);
        if (status != DPS_OK) {
            DPS_WARNPRINT("Failed to get PSK: %s\n", DPS_ErrTxt(ret));
        }
    }

    return status;
}

DPS_Status DPS_NetworkStart(DPS_Node* node, DPS_OnReceive cb)
{
    int ret;
    struct sockaddr_in6 addr;
    DPS_Status status;
    DPS_Network* net = node->network;

    DPS_DBGTRACE();

    status = MCastInit(net);
    if (status != DPS_OK) {
        goto Exit;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    net_addr_pton(AF_INET6, LOCAL_ADDR_6, &addr.sin6_addr);
    addr.sin6_port = 0;

    if (net->dtlsState != DTLS_DISABLED) {
        net->ucast6 = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_TLS_1_2);
    } else {
        net->ucast6 = zsock_socket(AF_INET6, SOCK_DGRAM, 0);
    }
    zsock_fcntl(net->ucast6, F_SETFL, O_NONBLOCK);
    ret = zsock_bind(net->ucast6, (struct sockaddr*)&addr, sizeof(addr));
    if (ret != 0) {
        status = DPS_ERR_NETWORK;
        goto Exit;
    }
    /*
     * Start the I/O completion thread
     */
    threadId = k_thread_create(&threadData,
            threadStack,
            K_THREAD_STACK_SIZEOF(threadStack),
            CallbackThread,
            node, net, cb,
            THREAD_PRIORITY, 0, K_NO_WAIT);

    node->port = GetPort(net->ucast6);
    DPS_DBGPRINT("Listening on port %d\n", node->port);

Exit:
    return status;
}

DPS_Status DPS_MCastSend(DPS_Node* node, void* appCtx, DPS_SendComplete sendCompleteCB)
{
    DPS_Network* net = node->network;
    int ret;
    struct sockaddr_in6 addr6;
    unsigned int len = (unsigned int)(node->txLen + node->txHdrLen);
    uint8_t* buf = node->txBuffer + DPS_TX_HEADER_SIZE - node->txHdrLen;

    DPS_DBGTRACE();

    if (net->sendCB) {
        return DPS_ERR_BUSY;
    }

    memset(&addr6, 0, sizeof(addr6));
    ret = net_addr_pton(AF_INET6, COAP_MCAST_ALL_NODES_LINK_LOCAL_6, &addr6.sin6_addr);
    if (ret) {
        return DPS_ERR_NETWORK;
    }
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(COAP_UDP_PORT);

    ret = zsock_sendto(net->mcast6, buf, len, 0, (struct sockaddr*)&addr6, sizeof(struct sockaddr_storage));
    if (ret < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            net->sendCB = NULL;
            return DPS_ERR_NETWORK;
        }
    } else {
        /* TODO - can this happen with a non-blocking socket? */
    }
    return DPS_OK;
}

DPS_Status DPS_UnicastSend(DPS_Node* node, const DPS_NodeAddress* dest, void* appCtx, DPS_SendComplete sendCompleteCB)
{
    int ret;
    DPS_Status status = DPS_OK;
    DPS_Network* net = node->network;
    unsigned int len = (unsigned int)(node->txLen + node->txHdrLen);
    uint8_t* buf = node->txBuffer + DPS_TX_HEADER_SIZE - node->txHdrLen;

    DPS_DBGTRACE();

    if (net->sendCB) {
        return DPS_ERR_BUSY;
    }

    if (net->dtlsState == DTLS_ENABLED) {
        status = ConfigureDTLS(node, net->ucast6, DTLS_IS_CLIENT);
        if (status != DPS_OK) {
            return status;
        }
    }

    net->sendCB = sendCompleteCB;
    net->appData = appCtx;
    ret = zsock_sendto(net->ucast6, buf, len, 0, (struct sockaddr*)dest, sizeof(struct sockaddr_storage));
    if (ret < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            net->sendCB = NULL;
            return DPS_ERR_NETWORK;
        }
    } else {
        /* TODO - can this happen with a non-blocking socket? */
    }
    return DPS_OK;
}
