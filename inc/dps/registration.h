/*
 *******************************************************************
 *
 * Copyright 2016 Intel Corporation All rights reserved.
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

#ifndef _DPS_REGISTRATION_H
#define _DPS_REGISTRATION_H

#include <dps/dps.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * APIs for interacting with a registration service
 */

extern const char* DPS_RegistryTopicString;

#define DPS_CANDIDATE_TRYING   0x01  /** An attempt is being made link to a candidate */
#define DPS_CANDIDATE_FAILED   0x02  /** An attempt to link to a candidate was attempted but failed */
#define DPS_CANDIDATE_LINKED   0x04  /** Registration is currently linked */
#define DPS_CANDIDATE_UNLINKED 0x08  /** Registration was linked but is currently not linked */
#define DPS_CANDIDATE_INVALID  0x10  /** This is a invalid candidate address for linking */

/**
 * Registration entryg
 */
typedef struct _DPS_Registration {
    uint8_t flags;
    uint16_t port;
    char* host;
} DPS_Registration;

/**
 * For returning a list of candidate remote nodes
 */
typedef struct _DPS_RegistrationList {
    uint8_t size;     /* Size of the list */
    uint8_t count;    /* number of entries currently in the list */
    DPS_Registration list[1];
} DPS_RegistrationList;

/**
 * Create an empty regisration list of the specified size
 */
DPS_RegistrationList* DPS_CreateRegistrationList(uint8_t size);

/**
 * Destroy a regisration list and free resources
 */
void DPS_DestroyRegistrationList(DPS_RegistrationList* regs);

/**
 * Function prototype for callback called when DPS_Registration_Put() completes
 *
 * @param status      DPS_OK if the registration was made
 * @param data        Caller supplied data passed into the DPS_Registration_Put()
 *
 */
typedef void (*DPS_OnRegPutComplete)(DPS_Status status, void* data);

/**
 * Resolve the host and port of a registration service and register a local node with
 * that service.
 *
 * @param node          The local node to register
 * @param host          The host name or IP address to register with
 * @param port          The port number
 * @param tenantString  Topic string indentifying the tenant
 * @param cb            Callback called when the registration completes.
 * @param data          Caller provided data to be passed to the callback function
 *
 */
DPS_Status DPS_Registration_Put(DPS_Node* node, const char* host, uint16_t port, const char* tenantString, DPS_OnRegPutComplete cb, void* data);

/**
 * Synchronous version of DPS_RegistrationPut(). This function blocks until the operations is
 * complete.
 *
 * @param node          The local node to register
 * @param host          The host name or IP address to register with
 * @param port          The port number
 * @param tenantString  Topic string indentifying the tenant
 *
 */
DPS_Status DPS_Registration_PutSyn(DPS_Node* node, const char* host, uint16_t port, const char* tenantString);

/**
 * Function prototype for callback called when DPS_Registration_Get() completes
 *
 * @param regs   Struct containing the list of candidate passed in to DPS_Registration_Get()
 * @param status DPS_OK if the get completed succesfully - the registration list might be empty,
 * @param data   Caller supplied data passed into the DPS_Registration_Get()
 */
typedef void (*DPS_OnRegGetComplete)(DPS_RegistrationList* regs, DPS_Status status, void* data);

/**
 * Resolve the host and port of a registration service and lookup the addresses
 * registered with that service.
 *
 * @param node          The node
 * @param host          The host name or IP address to register with
 * @param port          The port number
 * @param tenantString  Topic string indentifying the tenant
 * @param regs          Registration list for accumulating the results. The count field must be
 *                      initialized with the maximum number of registrations to be returned. The
 *                      candidate list pointer must remanin valid until the callback is called.
 * @param cb            The callback to call with the result
 * @param data          Called supplied data to be passed to the callback
 *
 */
DPS_Status DPS_Registration_Get(DPS_Node* node, const char* host, uint16_t port, const char* tenantString, DPS_RegistrationList* regs, DPS_OnRegGetComplete cb, void* data);

/**
 * A synchronous version of DPS_RegistrationGet() this function blocks until the candidate list has
 * been populated or the request times out.
 *
 * @param node          The node
 * @param host          The host name or IP address to register with
 * @param port          The port number
 * @param tenantString  Topic string indentifying the tenant
 * @param regs          Registration list for accumulating the results.
 *
 */
DPS_Status DPS_Registration_GetSyn(DPS_Node* node, const char* host, uint16_t port, const char* tenantString, DPS_RegistrationList* regs);

/**
 * Function prototype for callback called when DPS_Registration_LinkTo() completes
 *
 * @param regs    The list of registrations addressess passed in to DPS_Registration_LinkTo().
 * @param addr    The address if the remote if status == DPS_OK
 * @param status  - DPS_OK if a link was sucessfully established
 *                - DPS_ERR_NO_ROUTE if a link could not be established
 * @param data    Caller supplied data passed into the DPS_Registration_LinkTo()
 *
 */
typedef void (*DPS_OnRegLinkToComplete)(DPS_Node* node, DPS_RegistrationList* regs, DPS_NodeAddress* addr, DPS_Status status, void* data);

/**
 * Randomly select a remote candidate to link to.
 *
 * @param node  The local node to link
 * @param regs  The list of candidate registrations to try to link to
 * @param cb    The callback to call with the result
 * @param data  Called supplied data to be passed to the callback
 *
 * @return  DPS_OK if a link is being tried
 *          DPS_ERR_NO_ROUTE if no new links can be established
 */
DPS_Status DPS_Registration_LinkTo(DPS_Node* node, DPS_RegistrationList* regs, DPS_OnRegLinkToComplete cb, void* data);

/**
 * Synchronous version of Registration_LinkTo
 *
 * @param node  The local node to link
 * @param regs  The list of candidate registrations to try to link to
 * @param addr  Set to the address of the linked candidate
 *
 */
DPS_Status DPS_Registration_LinkToSyn(DPS_Node* node, DPS_RegistrationList* regs, DPS_NodeAddress* addr);

#ifdef __cplusplus
}
#endif

#endif
