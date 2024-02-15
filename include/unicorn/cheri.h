/*
    Unicorn Engine CHERI exports
    Copyright (C) 2024 Zhuo Ying Jiang Li <zyj20 [at] cl.cam.ac.uk>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
   USA
*/

#ifndef UNICORN_CHERI_H
#define UNICORN_CHERI_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

// XXXR3: this is assuming morello encodings. Check cheri_compressed_cap_128m.h
typedef enum uc_cheri_perm {
    UC_CHERI_PERM_GLOBAL = 1 << 0,
    UC_CHERI_PERM_EXECUTIVE = 1 << 1,
    UC_CHERI_PERM_MUTABLE_LOAD = 1 << 6,
    UC_CHERI_PERM_SETCID = 1 << 7,
    UC_CHERI_PERM_BRANCH_SEALED_PAIR = 1 << 8,
    UC_CHERI_PERM_CINVOKE = UC_CHERI_PERM_BRANCH_SEALED_PAIR,
    UC_CHERI_PERM_SYSTEM = 1 << 9,
    UC_CHERI_PERM_ACCESS_SYS_REGS = UC_CHERI_PERM_SYSTEM,
    UC_CHERI_PERM_UNSEAL = 1 << 10,
    UC_CHERI_PERM_SEAL = 1 << 11,
    UC_CHERI_PERM_STORE_LOCAL = 1 << 12,
    UC_CHERI_PERM_STORE_CAP = 1 << 13,
    UC_CHERI_PERM_LOAD_CAP = 1 << 14,
    UC_CHERI_PERM_EXECUTE = 1 << 15,
    UC_CHERI_PERM_STORE = 1 << 16,
    UC_CHERI_PERM_LOAD = 1 << 17,

    UC_CHERI_PERMS_ALL = 0x3FFFF,
} uc_cheri_perm;

typedef enum uc_cheri_uperm {
    UC_CHERI_UPERMS_ALL = 0,
} uc_cheri_uperm;

typedef enum uc_cheri_otype {
    UC_CHERI_OTYPE_UNSEALED = 0,
    UC_CHERI_OTYPE_SENTRY = 1,
    UC_CHERI_OTYPE_LOAD_PAIR_BRANCH = 2,
    UC_CHERI_OTYPE_LOAD_BRANCH = 3,
} uc_cheri_otype;

// capability type
typedef struct uc_cheri_cap {
    uint64_t address;
    uint64_t base;   /* Capability base addr */
    __uint128_t top; /* Capability top, it could use 65-bits */
    uint8_t tag;     /* Tag */
    uint32_t uperms; /* Software permissions */
    uint32_t perms;  /* Permissions */
    uint32_t otype;  /* Object type, eg. OTYPE_UNSEALED */
} uc_cheri_cap;

#ifdef __cplusplus
}
#endif

#endif
