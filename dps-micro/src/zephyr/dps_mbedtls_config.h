/* Use config file, to replace mbed defaults. It is set during
 * compilation with MBEDTLS_USER_CONFIG_FILE environment variable. */

#define MBEDTLS_DEPRECATED_REMOVED
#define MBEDTLS_NIST_KW_C
#define MBEDTLS_ECDSA_DETERMINISTIC

#define MBEDTLS_ENTROPY_C
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT
