/*
 * QEMU AArch64 CPU
 *
 * Copyright (c) 2013 Linaro Ltd
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include <exec/exec-all.h>

void arm_cpu_realizefn(struct uc_struct *uc, CPUState *dev);
void arm_cpu_class_init(struct uc_struct *uc, CPUClass *oc);
void arm_cpu_post_init(CPUState *obj);
void arm_cpu_initfn(struct uc_struct *uc, CPUState *obj);
ARMCPU *cpu_arm_init(struct uc_struct *uc);


static inline void set_feature(CPUARMState *env, int feature)
{
    env->features |= 1ULL << feature;
}

static void aarch64_a57_initfn(struct uc_struct *uc, CPUState *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);

    set_feature(&cpu->env, ARM_FEATURE_V8);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_GENERIC_TIMER);
    set_feature(&cpu->env, ARM_FEATURE_AARCH64);
    set_feature(&cpu->env, ARM_FEATURE_CBAR_RO);
    set_feature(&cpu->env, ARM_FEATURE_EL2);
    set_feature(&cpu->env, ARM_FEATURE_EL3);
    set_feature(&cpu->env, ARM_FEATURE_PMU);
    cpu->midr = 0x411fd070;
    cpu->revidr = 0x00000000;
    cpu->reset_fpsid = 0x41034070;
    cpu->isar.mvfr0 = 0x10110222;
    cpu->isar.mvfr1 = 0x12111111;
    cpu->isar.mvfr2 = 0x00000043;
    cpu->ctr = 0x8444c004;
    cpu->reset_sctlr = 0x00c50838;
    cpu->id_pfr0 = 0x00000131;
    cpu->id_pfr1 = 0x00011011;
    cpu->isar.id_dfr0 = 0x03010066;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x10101105;
    cpu->isar.id_mmfr1 = 0x40000000;
    cpu->isar.id_mmfr2 = 0x01260000;
    cpu->isar.id_mmfr3 = 0x02102211;
    cpu->isar.id_isar0 = 0x02101110;
    cpu->isar.id_isar1 = 0x13112111;
    cpu->isar.id_isar2 = 0x21232042;
    cpu->isar.id_isar3 = 0x01112131;
    cpu->isar.id_isar4 = 0x00011142;
    cpu->isar.id_isar5 = 0x00011121;
    cpu->isar.id_isar6 = 0;
    cpu->isar.id_aa64pfr0 = 0x00002222;
    cpu->isar.id_aa64dfr0 = 0x10305106;
    cpu->isar.id_aa64isar0 = 0x00011120;
    cpu->isar.id_aa64mmfr0 = 0x00001124;
    cpu->isar.dbgdidr = 0x3516d000;
    cpu->clidr = 0x0a200023;
    cpu->ccsidr[0] = 0x701fe00a; /* 32KB L1 dcache */
    cpu->ccsidr[1] = 0x201fe012; /* 48KB L1 icache */
    cpu->ccsidr[2] = 0x70ffe07a; /* 2048KB L2 cache */
    cpu->dcz_blocksize = 4; /* 64 bytes */
    cpu->gic_num_lrs = 4;
    cpu->gic_vpribits = 5;
    cpu->gic_vprebits = 5;
}

static void aarch64_morello_initfn(struct uc_struct *uc, CPUState *obj)
{
    // Can I just remove the a32 registers?
    // LETODO: Maybe stop using ifdef TARGET_CHERI and configure it from here
    // LETODO: Some registers have been fixed now, but this is still reporting
    // as an a72

    // It is unclear how closely this wants to match the real morello board
    //#define MATCH_MORELLO_CLOSELY

    ARMCPU *cpu = ARM_CPU(obj);
    uint64_t t;

    set_feature(&cpu->env, ARM_FEATURE_V8);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_GENERIC_TIMER);
    set_feature(&cpu->env, ARM_FEATURE_AARCH64);
    set_feature(&cpu->env, ARM_FEATURE_CBAR_RO);
    set_feature(&cpu->env, ARM_FEATURE_EL2);
    set_feature(&cpu->env, ARM_FEATURE_EL3); // XXXR3: CheriBSD disables EL3
    set_feature(&cpu->env, ARM_FEATURE_PMU);
    cpu->midr = 0x410fd083;
    cpu->revidr = 0x00000000;
    cpu->reset_fpsid = 0x41034080;
    cpu->isar.mvfr0 = 0x10110222;
    cpu->isar.mvfr1 = 0x12111111;
    cpu->isar.mvfr2 = 0x00000043;
    cpu->ctr = 0x8444c004;
    cpu->reset_sctlr = 0x00c50838;
    cpu->id_pfr0 = 0x00000131;
    cpu->id_pfr1 = 0x00011011;
    cpu->isar.id_dfr0 = 0x03010066;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x10201105;
    cpu->isar.id_mmfr1 = 0x40000000;
    cpu->isar.id_mmfr2 = 0x01260000;
    cpu->isar.id_mmfr3 = 0x02102211;
    cpu->isar.id_isar0 = 0x02101110;
    cpu->isar.id_isar1 = 0x13112111;
    cpu->isar.id_isar2 = 0x21232042;
    cpu->isar.id_isar3 = 0x01112131;
    cpu->isar.id_isar4 = 0x00011142;
    cpu->isar.id_isar5 = 0x00011121;

    /* These are enabled on morello but not yet implemented in QEMU */
    // t = FIELD_DP64(t, ID_AA64MMFR2, IESB, 1);
    // t = FIELD_DP64(t, ID_AA64PFR1, SBSS, 2);
    // t = FIELD_DP64(t, ID_AA64MMFR2, EVT, 2);

    // Processor Features
    t = cpu->isar.id_aa64pfr0;
    FIELD_DP64(t, ID_AA64PFR0, FP, 1, t);
    FIELD_DP64(t, ID_AA64PFR0, ADVSIMD, 1, t);
    FIELD_DP64(t, ID_AA64PFR0, EL0, 1, t);
    FIELD_DP64(t, ID_AA64PFR0, EL1, 1, t);
    FIELD_DP64(t, ID_AA64PFR0, EL2, 1, t);
    FIELD_DP64(t, ID_AA64PFR0, EL3, 1, t);
#ifdef MATCH_MORELLO_CLOSELY
    // RAS not actually implemented in QEMU
    // t = FIELD_DP64(t, ID_AA64PFR0, RAS, 1);
    t = FIELD_DP64(t, ID_AA64PFR0, CSV2, 1);
    t = FIELD_DP64(t, ID_AA64PFR0, CSV3, 1);
#endif
    cpu->isar.id_aa64pfr0 = t;

    t = cpu->isar.id_aa64pfr1;
    FIELD_DP64(t, ID_AA64PFR1, CE, 1, t);
    cpu->isar.id_aa64pfr1 = t;

    t = cpu->isar.id_aa64dfr0;
    FIELD_DP64(t, ID_AA64DFR0, PMUVER, 5, t); /* v8.4-PMU */
    // 4 breakpoints and watchpoints (field stores x - 1)
    FIELD_DP64(t, ID_AA64DFR0, BRPS, 8 - 1, t); /* v8.4-PMU */
    FIELD_DP64(t, ID_AA64DFR0, WRPS, 8 - 1, t); /* v8.4-PMU */
    cpu->isar.id_aa64dfr0 = t;

    // Instruction Set Attributes
    t = cpu->isar.id_aa64isar0;
    FIELD_DP64(t, ID_AA64ISAR0, AES, 2, t); /* AES + PMULL */
    FIELD_DP64(t, ID_AA64ISAR0, SHA1, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, SHA2, 2, t); /* SHA512 */
    FIELD_DP64(t, ID_AA64ISAR0, CRC32, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, ATOMIC, 2, t);
    FIELD_DP64(t, ID_AA64ISAR0, RDM, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, DP, 1, t);
    cpu->isar.id_aa64isar0 = t;

    t = cpu->isar.id_aa64isar1;
    FIELD_DP64(t, ID_AA64ISAR1, DPB, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, LRCPC, 1, t); /* ARMv8.3-RCPC */
    cpu->isar.id_aa64isar1 = t;

    // Memory model features
    t = cpu->isar.id_aa64mmfr0;
#ifdef MATCH_MORELLO_CLOSELY
    FIELD_DP64(t, ID_AA64MMFR0, SNSMEM, 1, t);
    FIELD_DP64(t, ID_AA64MMFR0, TGRAN16, 1, t);
    FIELD_DP64(t, ID_AA64MMFR0, TGRAN64, 0, t);
#else
    FIELD_DP64(t, ID_AA64MMFR0, TGRAN16, 0, t);
    FIELD_DP64(t, ID_AA64MMFR0, TGRAN64, 0b1111, t);
#endif
    FIELD_DP64(t, ID_AA64MMFR0, TGRAN4, 0, t);
    FIELD_DP64(t, ID_AA64MMFR0, PARANGE, 5, t); /* PARange: 48 bits */
    FIELD_DP64(t, ID_AA64MMFR0, ASIDBITS, 2, t);

    cpu->isar.id_aa64mmfr0 = t;

    t = cpu->isar.id_aa64mmfr1;
    // 2 would be HAF + DS, which would be useful, but tricky to implement.
    // Morello has it set.
    FIELD_DP64(t, ID_AA64MMFR1, HAFDBS, 0, t) /**/;
    FIELD_DP64(t, ID_AA64MMFR1, HPDS, 2, t); /* HPD+TTPBHA*/
    FIELD_DP64(t, ID_AA64MMFR1, LO, 1, t);
    FIELD_DP64(t, ID_AA64MMFR1, VH, 1, t);
    FIELD_DP64(t, ID_AA64MMFR1, PAN, 2, t);      /* PAN + ATS1E1 */
    FIELD_DP64(t, ID_AA64MMFR1, VMIDBITS, 2, t); /* VMID16 */
    FIELD_DP64(t, ID_AA64MMFR1, XNX, 1, t);      /* TTS2UXN */
    cpu->isar.id_aa64mmfr1 = t;

    t = cpu->isar.id_aa64mmfr2;
    FIELD_DP64(t, ID_AA64MMFR2, CCIDX, 0, t);
    FIELD_DP64(t, ID_AA64MMFR2, UAO, 1, t);
    FIELD_DP64(t, ID_AA64MMFR2, CNP, 1, t); /* TTCNP */
    cpu->isar.id_aa64mmfr2 = t;

    cpu->isar.dbgdidr = 0x3516d000;
    cpu->clidr = 0x0a200023;
    cpu->ccsidr[0] = 0x701fe00a; /* 32KB L1 dcache */
    cpu->ccsidr[1] = 0x201fe012; /* 48KB L1 icache */
    cpu->ccsidr[2] = 0x707fe07a; /* 1MB L2 cache */
    cpu->dcz_blocksize = 4;      /* 64 bytes */
    cpu->gic_num_lrs = 4;
    cpu->gic_vpribits = 5;
    cpu->gic_vprebits = 5;
}

static void aarch64_a53_initfn(struct uc_struct *uc, CPUState *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);

    set_feature(&cpu->env, ARM_FEATURE_V8);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_GENERIC_TIMER);
    set_feature(&cpu->env, ARM_FEATURE_AARCH64);
    set_feature(&cpu->env, ARM_FEATURE_CBAR_RO);
    set_feature(&cpu->env, ARM_FEATURE_EL2);
    set_feature(&cpu->env, ARM_FEATURE_EL3);
    set_feature(&cpu->env, ARM_FEATURE_PMU);
    cpu->midr = 0x410fd034;
    cpu->revidr = 0x00000000;
    cpu->reset_fpsid = 0x41034070;
    cpu->isar.mvfr0 = 0x10110222;
    cpu->isar.mvfr1 = 0x12111111;
    cpu->isar.mvfr2 = 0x00000043;
    cpu->ctr = 0x84448004; /* L1Ip = VIPT */
    cpu->reset_sctlr = 0x00c50838;
    cpu->id_pfr0 = 0x00000131;
    cpu->id_pfr1 = 0x00011011;
    cpu->isar.id_dfr0 = 0x03010066;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x10101105;
    cpu->isar.id_mmfr1 = 0x40000000;
    cpu->isar.id_mmfr2 = 0x01260000;
    cpu->isar.id_mmfr3 = 0x02102211;
    cpu->isar.id_isar0 = 0x02101110;
    cpu->isar.id_isar1 = 0x13112111;
    cpu->isar.id_isar2 = 0x21232042;
    cpu->isar.id_isar3 = 0x01112131;
    cpu->isar.id_isar4 = 0x00011142;
    cpu->isar.id_isar5 = 0x00011121;
    cpu->isar.id_isar6 = 0;
    cpu->isar.id_aa64pfr0 = 0x00002222;
    cpu->isar.id_aa64dfr0 = 0x10305106;
    cpu->isar.id_aa64isar0 = 0x00011120;
    cpu->isar.id_aa64mmfr0 = 0x00001122; /* 40 bit physical addr */
    cpu->isar.dbgdidr = 0x3516d000;
    cpu->clidr = 0x0a200023;
    cpu->ccsidr[0] = 0x700fe01a; /* 32KB L1 dcache */
    cpu->ccsidr[1] = 0x201fe00a; /* 32KB L1 icache */
    cpu->ccsidr[2] = 0x707fe07a; /* 1024KB L2 cache */
    cpu->dcz_blocksize = 4; /* 64 bytes */
    cpu->gic_num_lrs = 4;
    cpu->gic_vpribits = 5;
    cpu->gic_vprebits = 5;
}

static void aarch64_a72_initfn(struct uc_struct *uc, CPUState *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);

    set_feature(&cpu->env, ARM_FEATURE_V8);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_GENERIC_TIMER);
    set_feature(&cpu->env, ARM_FEATURE_AARCH64);
    set_feature(&cpu->env, ARM_FEATURE_CBAR_RO);
    set_feature(&cpu->env, ARM_FEATURE_EL2);
    set_feature(&cpu->env, ARM_FEATURE_EL3);
    set_feature(&cpu->env, ARM_FEATURE_PMU);
    cpu->midr = 0x410fd083;
    cpu->revidr = 0x00000000;
    cpu->reset_fpsid = 0x41034080;
    cpu->isar.mvfr0 = 0x10110222;
    cpu->isar.mvfr1 = 0x12111111;
    cpu->isar.mvfr2 = 0x00000043;
    cpu->ctr = 0x8444c004;
    cpu->reset_sctlr = 0x00c50838;
    cpu->id_pfr0 = 0x00000131;
    cpu->id_pfr1 = 0x00011011;
    cpu->isar.id_dfr0 = 0x03010066;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x10201105;
    cpu->isar.id_mmfr1 = 0x40000000;
    cpu->isar.id_mmfr2 = 0x01260000;
    cpu->isar.id_mmfr3 = 0x02102211;
    cpu->isar.id_isar0 = 0x02101110;
    cpu->isar.id_isar1 = 0x13112111;
    cpu->isar.id_isar2 = 0x21232042;
    cpu->isar.id_isar3 = 0x01112131;
    cpu->isar.id_isar4 = 0x00011142;
    cpu->isar.id_isar5 = 0x00011121;
    cpu->isar.id_aa64pfr0 = 0x00002222;
    cpu->isar.id_aa64dfr0 = 0x10305106;
    cpu->isar.id_aa64isar0 = 0x00011120;
    cpu->isar.id_aa64mmfr0 = 0x00001124;
    cpu->isar.dbgdidr = 0x3516d000;
    cpu->clidr = 0x0a200023;
    cpu->ccsidr[0] = 0x701fe00a; /* 32KB L1 dcache */
    cpu->ccsidr[1] = 0x201fe012; /* 48KB L1 icache */
    cpu->ccsidr[2] = 0x707fe07a; /* 1MB L2 cache */
    cpu->dcz_blocksize = 4; /* 64 bytes */
    cpu->gic_num_lrs = 4;
    cpu->gic_vpribits = 5;
    cpu->gic_vprebits = 5;
}

/* -cpu max: if KVM is enabled, like -cpu host (best possible with this host);
 * otherwise, a CPU with as many features enabled as our emulation supports.
 * The version of '-cpu max' for qemu-system-arm is defined in cpu.c;
 * this only needs to handle 64 bits.
 */
static void aarch64_max_initfn(struct uc_struct *uc, CPUState *obj)
{

    uint64_t t;
    uint32_t u;
    ARMCPU *cpu = ARM_CPU(obj);

    aarch64_a57_initfn(uc, obj);

    /*
     * Reset MIDR so the guest doesn't mistake our 'max' CPU type for a real
     * one and try to apply errata workarounds or use impdef features we
     * don't provide.
     * An IMPLEMENTER field of 0 means "reserved for software use";
     * ARCHITECTURE must be 0xf indicating "v7 or later, check ID registers
     * to see which features are present";
     * the VARIANT, PARTNUM and REVISION fields are all implementation
     * defined and we choose to define PARTNUM just in case guest
     * code needs to distinguish this QEMU CPU from other software
     * implementations, though this shouldn't be needed.
     */
    FIELD_DP64(0, MIDR_EL1, IMPLEMENTER, 0, t);
    FIELD_DP64(t, MIDR_EL1, ARCHITECTURE, 0xf ,t);
    FIELD_DP64(t, MIDR_EL1, PARTNUM, 'Q', t);
    FIELD_DP64(t, MIDR_EL1, VARIANT, 0, t);
    FIELD_DP64(t, MIDR_EL1, REVISION, 0, t);
    cpu->midr = t;

    t = cpu->isar.id_aa64isar0;
    FIELD_DP64(t, ID_AA64ISAR0, AES, 2, t); /* AES + PMULL */
    FIELD_DP64(t, ID_AA64ISAR0, SHA1, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, SHA2, 2, t); /* SHA512 */
    FIELD_DP64(t, ID_AA64ISAR0, CRC32, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, ATOMIC, 2, t);
    FIELD_DP64(t, ID_AA64ISAR0, RDM, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, SHA3, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, SM3, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, SM4, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, DP, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, FHM, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, TS, 2, t); /* v8.5-CondM */
    FIELD_DP64(t, ID_AA64ISAR0, RNDR, 1, t);
    cpu->isar.id_aa64isar0 = t;

    t = cpu->isar.id_aa64isar1;
    FIELD_DP64(t, ID_AA64ISAR1, DPB, 2, t);
    FIELD_DP64(t, ID_AA64ISAR1, JSCVT, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, FCMA, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, APA, 1, t); /* PAuth, architected only */
    FIELD_DP64(t, ID_AA64ISAR1, API, 0, t);
    FIELD_DP64(t, ID_AA64ISAR1, GPA, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, GPI, 0, t);
    FIELD_DP64(t, ID_AA64ISAR1, SB, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, SPECRES, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, FRINTTS, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, LRCPC, 2, t); /* ARMv8.4-RCPC */
    cpu->isar.id_aa64isar1 = t;

    t = cpu->isar.id_aa64pfr0;
    FIELD_DP64(t, ID_AA64PFR0, SVE, 1, t);
    FIELD_DP64(t, ID_AA64PFR0, FP, 1, t);
    FIELD_DP64(t, ID_AA64PFR0, ADVSIMD, 1, t);
    cpu->isar.id_aa64pfr0 = t;

    t = cpu->isar.id_aa64pfr1;
    FIELD_DP64(t, ID_AA64PFR1, BT, 1, t);
    cpu->isar.id_aa64pfr1 = t;

    t = cpu->isar.id_aa64mmfr1;
    FIELD_DP64(t, ID_AA64MMFR1, HPDS, 1, t); /* HPD */
    FIELD_DP64(t, ID_AA64MMFR1, LO, 1, t);
    FIELD_DP64(t, ID_AA64MMFR1, VH, 1, t);
    FIELD_DP64(t, ID_AA64MMFR1, PAN, 2, t); /* ATS1E1 */
    FIELD_DP64(t, ID_AA64MMFR1, VMIDBITS, 2, t); /* VMID16 */
    cpu->isar.id_aa64mmfr1 = t;

    t = cpu->isar.id_aa64mmfr2;
    FIELD_DP64(t, ID_AA64MMFR2, UAO, 1, t);
    FIELD_DP64(t, ID_AA64MMFR2, CNP, 1, t); /* TTCNP */
    cpu->isar.id_aa64mmfr2 = t;

    /* Replicate the same data to the 32-bit id registers.  */
    u = cpu->isar.id_isar5;
    FIELD_DP32(u, ID_ISAR5, AES, 2, u); /* AES + PMULL */
    FIELD_DP32(u, ID_ISAR5, SHA1, 1, u);
    FIELD_DP32(u, ID_ISAR5, SHA2, 1, u);
    FIELD_DP32(u, ID_ISAR5, CRC32, 1, u);
    FIELD_DP32(u, ID_ISAR5, RDM, 1, u);
    FIELD_DP32(u, ID_ISAR5, VCMA, 1, u);
    cpu->isar.id_isar5 = u;

    u = cpu->isar.id_isar6;
    FIELD_DP32(u, ID_ISAR6, JSCVT, 1, u);
    FIELD_DP32(u, ID_ISAR6, DP, 1, u);
    FIELD_DP32(u, ID_ISAR6, FHM, 1, u);
    FIELD_DP32(u, ID_ISAR6, SB, 1, u);
    FIELD_DP32(u, ID_ISAR6, SPECRES, 1, u);
    cpu->isar.id_isar6 = u;

    u = cpu->isar.id_mmfr3;
    FIELD_DP32(u, ID_MMFR3, PAN, 2, u); /* ATS1E1 */
    cpu->isar.id_mmfr3 = u;

    u = cpu->isar.id_mmfr4;
    FIELD_DP32(u, ID_MMFR4, HPDS, 1, u); /* AA32HPD */
    FIELD_DP32(u, ID_MMFR4, AC2, 1, u); /* ACTLR2, HACTLR2 */
    FIELD_DP32(u, ID_MMFR4, CNP, 1, u); /* TTCNP */
    cpu->isar.id_mmfr4 = u;

    u = cpu->isar.id_aa64dfr0;
    FIELD_DP64(u, ID_AA64DFR0, PMUVER, 5, u); /* v8.4-PMU */
    cpu->isar.id_aa64dfr0 = u;

    u = cpu->isar.id_dfr0;
    FIELD_DP32(u, ID_DFR0, PERFMON, 5, u); /* v8.4-PMU */
    cpu->isar.id_dfr0 = u;
}

struct ARMCPUInfo {
    const char *name;
    void (*initfn)(struct uc_struct *uc, CPUState *obj);
};

static const ARMCPUInfo aarch64_cpus[] = {
    { .name = "cortex-a57",         .initfn = aarch64_a57_initfn },
    { .name = "cortex-a53",         .initfn = aarch64_a53_initfn },
    { .name = "cortex-a72",         .initfn = aarch64_a72_initfn },
    { .name = "morello",            .initfn = aarch64_morello_initfn },
    { .name = "max",                .initfn = aarch64_max_initfn },
};

ARMCPU *cpu_aarch64_init(struct uc_struct *uc)
{
    ARMCPU *cpu;
    CPUState *cs;
    CPUClass *cc;
    CPUARMState *env;

    cpu = calloc(1, sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }

    // XXXR3: TODO: if the CPU model is not morello and the C64 mode is explicitly set,
    // then emit a warning
    if (uc->cpu_model == INT_MAX) {
#ifdef TARGET_CHERI
        uc->cpu_model = UC_CPU_ARM64_MORELLO;
#else
        uc->cpu_model = UC_CPU_ARM64_A72;
#endif
    } else if (uc->cpu_model >= sizeof(aarch64_cpus)) {
        free(cpu);
        return NULL;
    }

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    uc->cpu = (CPUState *)cpu;

    /* init CPUClass */
    cpu_class_init(uc, cc);

    /* init ARMCPUClass */
    arm_cpu_class_init(uc, cc);

    /* init CPUState */
    cpu_common_initfn(uc, cs);

    /* init ARMCPU */
    arm_cpu_initfn(uc, cs);

    if (aarch64_cpus[uc->cpu_model].initfn) {
        aarch64_cpus[uc->cpu_model].initfn(uc, cs);
    }

    /* postinit ARMCPU */
    arm_cpu_post_init(cs);

    /* realize ARMCPU */
    arm_cpu_realizefn(uc, cs);

    // init address space
    cpu_address_space_init(cs, 0, cs->memory);

    qemu_init_vcpu(cs);

    env = &cpu->env;
    if (uc->mode & UC_MODE_BIG_ENDIAN) {
        for (int i = 0; i < 4; i ++) {
            env->cp15.sctlr_el[i] |= SCTLR_EE;
            env->cp15.sctlr_el[i] |= SCTLR_E0E;
        }
    }

    // Backward compatibility to enable FULL 64bits address space.
    env->pstate = PSTATE_MODE_EL1h;
    
    if (uc->mode & UC_MODE_C64) {
        env->pstate |= PSTATE_C64;
        // XXXR3: to set CAP_ENABLED
        env->cp15.cpacr_el1 |= CPTR_CEN_LO;
        env->cp15.cptr_el[3] |= CPTR_EC;
    }

    arm_rebuild_hflags(env);

    return cpu;
}
