/**
 * SGX compatibility stubs for mcl library
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// mcl uses getenv to detect CPU features
// In SGX we return NULL to use default/safest code paths
char* getenv(const char* name) {
    (void)name;
    return NULL;
}

#ifdef __cplusplus
}
#endif
