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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

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
    __uint128_t top;      /* Capability top, it could use 65-bits */
    uint8_t tag;          /* Tag */
    uint32_t uperms;      /* Software permissions */
    uint32_t perms;       /* Permissions */
    uint32_t otype;        /* Object type, eg. OTYPE_UNSEALED */
} uc_cheri_cap;

#ifdef __cplusplus
}
#endif

#endif
