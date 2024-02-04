/* TODO: License */

#ifndef UNICORN_CHERI_H
#define UNICORN_CHERI_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

// capability type
typedef struct uc_cheri_cap {
    uint64_t address;     
    uint64_t base;        /* Capability base addr */
    __uint128_t top;        /* Capability top, it could use 65-bits */
    uint8_t tag;          /* Tag */
    uint32_t uperms;      /* Software permissions */
    uint32_t perms;       /* Permissions */
    uint32_t type;        /* Object type, eg. OTYPE_UNSEALED */
} uc_cheri_cap;

#ifdef __cplusplus
}
#endif

#endif
