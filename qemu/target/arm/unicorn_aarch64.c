/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "qemu/typedefs.h"
#include "unicorn/unicorn.h"
#include "sysemu/cpus.h"
#include "cpu.h"
#include "kvm-consts.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "unicorn.h"

// #include "cheri_compressed_cap_common.h"  // the macro is undefined at the end of the file!

#ifdef TARGET_CHERI

#define CC_FORMAT_LOWER 128m
#define CC_FORMAT_UPPER 128M

#define _cc_N(name) _CC_CONCAT(_CC_CONCAT(_CC_CONCAT(cc, CC_FORMAT_LOWER), _), name)
#define _CC_N(name) _CC_CONCAT(_CC_CONCAT(_CC_CONCAT(CC, CC_FORMAT_UPPER), _), name)

#endif

ARMCPU *cpu_aarch64_init(struct uc_struct *uc);

static void arm64_set_pc(struct uc_struct *uc, uint64_t address)
{
#ifdef TARGET_CHERI
    set_max_perms_capability(&((CPUARMState *)uc->cpu->env_ptr)->pc.cap, address);
#else
    set_aarch_reg_value(&((CPUARMState *)uc->cpu->env_ptr)->pc, address);
#endif
}

static uint64_t arm64_get_pc(struct uc_struct *uc)
{
    return get_aarch_reg_as_x(&((CPUARMState *)uc->cpu->env_ptr)->pc);
}

static void arm64_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    ARMCPU *cpu = (ARMCPU *)tcg_ctx->uc->cpu;
    CPUTLBDesc *d = cpu->neg.tlb.d;
    CPUTLBDescFast *f = cpu->neg.tlb.f;
    CPUTLBDesc *desc;
    CPUTLBDescFast *fast;
    ARMELChangeHook *entry, *next;
    CPUARMState *env = &cpu->env;
    uint32_t nr;

    release_common(ctx);
    for (i = 0; i < NB_MMU_MODES; i++) {
        desc = &(d[i]);
        fast = &(f[i]);
        g_free(desc->iotlb);
        g_free(fast->table);
    }

    QLIST_FOREACH_SAFE(entry, &cpu->pre_el_change_hooks, node, next)
    {
        QLIST_SAFE_REMOVE(entry, node);
        g_free(entry);
    }
    QLIST_FOREACH_SAFE(entry, &cpu->el_change_hooks, node, next)
    {
        QLIST_SAFE_REMOVE(entry, node);
        g_free(entry);
    }

    if (arm_feature(env, ARM_FEATURE_PMSA) &&
        arm_feature(env, ARM_FEATURE_V7)) {
        nr = cpu->pmsav7_dregion;
        if (nr) {
            if (arm_feature(env, ARM_FEATURE_V8)) {
                g_free(env->pmsav8.rbar[M_REG_NS]);
                g_free(env->pmsav8.rlar[M_REG_NS]);
                if (arm_feature(env, ARM_FEATURE_M_SECURITY)) {
                    g_free(env->pmsav8.rbar[M_REG_S]);
                    g_free(env->pmsav8.rlar[M_REG_S]);
                }
            } else {
                g_free(env->pmsav7.drbar);
                g_free(env->pmsav7.drsr);
                g_free(env->pmsav7.dracr);
            }
        }
    }
    if (arm_feature(env, ARM_FEATURE_M_SECURITY)) {
        nr = cpu->sau_sregion;
        if (nr) {
            g_free(env->sau.rbar);
            g_free(env->sau.rlar);
        }
    }

    g_free(cpu->cpreg_indexes);
    g_free(cpu->cpreg_values);
    g_free(cpu->cpreg_vmstate_indexes);
    g_free(cpu->cpreg_vmstate_values);
    g_hash_table_destroy(cpu->cp_regs);
}

// This is called at uc_init
void arm64_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;
#ifdef TARGET_CHERI
    reset_capregs(env);
    set_max_perms_capability(&env->pc.cap, 0);
#else
    memset(env->xregs, 0, sizeof(env->xregs));
    env->pc = 0;
#endif
}

static uc_err read_cp_reg(CPUARMState *env, uc_arm64_cp_reg *cp)
{
    ARMCPU *cpu = ARM_CPU(env->uc->cpu);
    const ARMCPRegInfo *ri = get_arm_cp_reginfo(
        cpu->cp_regs, ENCODE_AA64_CP_REG(CP_REG_ARM64_SYSREG_CP, cp->crn,
                                         cp->crm, cp->op0, cp->op1, cp->op2));

    if (!ri) {
        return UC_ERR_ARG;
    }
    // XXXR3: todo, migrate to caps
    cp->val = read_raw_cp_reg(env, ri);

    return UC_ERR_OK;
}

static uc_err write_cp_reg(CPUARMState *env, uc_arm64_cp_reg *cp)
{
    ARMCPU *cpu = ARM_CPU(env->uc->cpu);
    const ARMCPRegInfo *ri = get_arm_cp_reginfo(
        cpu->cp_regs, ENCODE_AA64_CP_REG(CP_REG_ARM64_SYSREG_CP, cp->crn,
                                         cp->crm, cp->op0, cp->op1, cp->op2));

    if (!ri) {
        return UC_ERR_ARG;
    }
    // XXXR3: todo, migrate to caps
    write_raw_cp_reg(env, ri, cp->val);

    return UC_ERR_OK;
}

#ifdef TARGET_CHERI

static uc_err read_cap_reg(CPUARMState *env, unsigned int regid, uc_cheri_cap *cap)
{
    cap_register_t *capreg = get_readonly_capreg(env, regid);

    cap->address = capreg->_cr_cursor;
    cap->base = capreg->cr_base;
    cap->top = capreg->_cr_top;
    cap->tag = capreg->cr_tag;
    cap->uperms = cap_get_uperms(capreg);
    cap->perms = cap_get_perms(capreg);
    cap->type = cap_get_otype_unsigned(capreg);

    return UC_ERR_OK;
}

static uc_err write_cap_reg(CPUARMState *env, unsigned int regid, uc_cheri_cap *cap)
{
    cap_register_t capreg;
    memset(&capreg, 0, sizeof(capreg));
    capreg._cr_cursor = cap->address;
    capreg.cr_base = cap->base;
    capreg._cr_top = cap->top;
    capreg.cr_tag = cap->tag;
    // encode permissions and otype FIXME
    capreg.cr_pesbt = _CC_ENCODE_FIELD(_CC_N(UPERMS_ALL), UPERMS) | _CC_ENCODE_FIELD(_CC_N(PERMS_ALL), HWPERMS) |
                    _CC_ENCODE_FIELD(_CC_N(OTYPE_UNSEALED), OTYPE);
    
    // compress
    bool exact = false;
    capreg.cr_exp = CC128M_RESET_EXP;
    uint32_t new_ebt = cc128m_compute_ebt(cap->base, cap->top, NULL, &exact);
    uint64_t new_base;
    __uint128_t new_top;
    bool new_bounds_valid = cc128m_compute_base_top(cc128m_extract_bounds_bits(_CC_ENCODE_FIELD(new_ebt, EBT)),
                                                    capreg._cr_cursor, &new_base, &new_top);
    // see setbounds_impl
    cc128m_update_ebt(&capreg, new_ebt);
    capreg.cr_bounds_valid = new_bounds_valid;
    capreg.cr_extra = CREG_FULLY_DECOMPRESSED;

    update_capreg(env, regid, &capreg);

    // printf("tag: %x\n,", capreg.cr_tag);
    // printf("bounds_valid: %d\n,", capreg.cr_bounds_valid);
    // printf cap_get_length()

    // cap_register_t capreg = CAP_cc(make_max_perms_cap)(0, cap->address, CAP_MAX_TOP);
    // capreg.cr_extra = CREG_FULLY_DECOMPRESSED;
    // update_capreg(env, regid, &capreg);

    // XXXR3: todo, warn when the bounds are not exact
    return UC_ERR_OK;
}

#endif

static uc_err reg_read(CPUARMState *env, unsigned int regid, void *value)
{
    uc_err ret = UC_ERR_OK;

    if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
        regid += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
    }
#ifdef TARGET_CHERI
    if (regid >= UC_ARM64_REG_C0 && regid <= UC_ARM64_REG_C28) {
        ret = read_cap_reg(env, regid - UC_ARM64_REG_C0, (uc_cheri_cap *)value);
    } else
#endif
    if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
        *(int64_t *)value = arm_get_xreg(env, regid - UC_ARM64_REG_X0);
    } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
        *(int32_t *)value = READ_DWORD(arm_get_xreg(env, regid - UC_ARM64_REG_W0));
    } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) { // FIXME
        float64 *dst = (float64 *)value;
        uint32_t reg_index = regid - UC_ARM64_REG_Q0;
        dst[0] = env->vfp.zregs[reg_index].d[0];
        dst[1] = env->vfp.zregs[reg_index].d[1];
    } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
        *(float64 *)value = env->vfp.zregs[regid - UC_ARM64_REG_D0].d[0];
    } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
        *(int32_t *)value =
            READ_DWORD(env->vfp.zregs[regid - UC_ARM64_REG_S0].d[0]);
    } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
        *(int16_t *)value =
            READ_WORD(env->vfp.zregs[regid - UC_ARM64_REG_H0].d[0]);
    } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
        *(int8_t *)value =
            READ_BYTE_L(env->vfp.zregs[regid - UC_ARM64_REG_B0].d[0]);
    } else if (regid >= UC_ARM64_REG_ELR_EL0 && regid <= UC_ARM64_REG_ELR_EL3) {
        *(uint64_t *)value = get_aarch_reg_as_x(&env->elr_el[regid - UC_ARM64_REG_ELR_EL0]); 
    } else if (regid >= UC_ARM64_REG_SP_EL0 && regid <= UC_ARM64_REG_SP_EL3) {
        *(uint64_t *)value = get_aarch_reg_as_x(&env->sp_el[regid - UC_ARM64_REG_SP_EL0]);
    } else if (regid >= UC_ARM64_REG_ESR_EL0 && regid <= UC_ARM64_REG_ESR_EL3) {
        *(uint64_t *)value = env->cp15.esr_el[regid - UC_ARM64_REG_ESR_EL0];
    } else if (regid >= UC_ARM64_REG_FAR_EL0 && regid <= UC_ARM64_REG_FAR_EL3) {
        *(uint64_t *)value = env->cp15.far_el[regid - UC_ARM64_REG_FAR_EL0];
    } else if (regid >= UC_ARM64_REG_VBAR_EL0 &&
               regid <= UC_ARM64_REG_VBAR_EL3) {
        *(uint64_t *)value = get_aarch_reg_as_x(&env->cp15.vbar_el[regid - UC_ARM64_REG_VBAR_EL0]);
    } else {
        switch (regid) {
        default:
            break;
        case UC_ARM64_REG_CPACR_EL1:
            *(uint32_t *)value = env->cp15.cpacr_el1;
            break;
        case UC_ARM64_REG_TPIDR_EL0:
            *(int64_t *)value = get_aarch_reg_as_x(&env->cp15.tpidr_el[0]);
            break;
        case UC_ARM64_REG_TPIDRRO_EL0:
            *(int64_t *)value = get_aarch_reg_as_x(&env->cp15.tpidrro_el[0]);
            break;
        case UC_ARM64_REG_TPIDR_EL1:
            *(int64_t *)value = get_aarch_reg_as_x(&env->cp15.tpidr_el[1]);
            break;
        case UC_ARM64_REG_X29:
            *(int64_t *)value = arm_get_xreg(env, 29);
            break;
        case UC_ARM64_REG_X30:
            *(int64_t *)value = arm_get_xreg(env, 30);
            break;
        case UC_ARM64_REG_PC:
#ifdef TARGET_CHERI
            cap_register_t *pcc = _cheri_get_pcc_unchecked(env);
            ((uc_cheri_cap *)value)->address = pcc->_cr_cursor;
            ((uc_cheri_cap *)value)->base = pcc->cr_base;
            ((uc_cheri_cap *)value)->top = pcc->_cr_top;
            ((uc_cheri_cap *)value)->tag = pcc->cr_tag;
            ((uc_cheri_cap *)value)->uperms = cap_get_uperms(pcc);
            ((uc_cheri_cap *)value)->perms = cap_get_perms(pcc);
            ((uc_cheri_cap *)value)->type = cap_get_otype_unsigned(pcc);
#else
            *(uint64_t *)value = get_aarch_reg_as_x(&env->pc);
#endif
            break;
        case UC_ARM64_REG_SP:
            *(int64_t *)value = arm_get_xreg(env, 31);
            break;
        case UC_ARM64_REG_NZCV:
            *(int32_t *)value = cpsr_read(env) & CPSR_NZCV;
            break;
        case UC_ARM64_REG_PSTATE:
            *(uint32_t *)value = pstate_read(env);
            break;
        case UC_ARM64_REG_TTBR0_EL1:
            *(uint64_t *)value = env->cp15.ttbr0_el[1];
            break;
        case UC_ARM64_REG_TTBR1_EL1:
            *(uint64_t *)value = env->cp15.ttbr1_el[1];
            break;
        case UC_ARM64_REG_PAR_EL1:
            *(uint64_t *)value = env->cp15.par_el[1];
            break;
        case UC_ARM64_REG_MAIR_EL1:
            *(uint64_t *)value = env->cp15.mair_el[1];
            break;
        case UC_ARM64_REG_CP_REG:
            ret = read_cp_reg(env, (uc_arm64_cp_reg *)value);
            break;
        case UC_ARM64_REG_FPCR:
            *(uint32_t *)value = vfp_get_fpcr(env);
            break;
        case UC_ARM64_REG_FPSR:
            *(uint32_t *)value = vfp_get_fpsr(env);
            break;
        }
    }

    return ret;
}

static uc_err reg_write(CPUARMState *env, unsigned int regid, const void *value)
{
    uc_err ret = UC_ERR_OK;

    if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
        regid += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
    }
#ifdef TARGET_CHERI
    if (regid >= UC_ARM64_REG_C0 && regid <= UC_ARM64_REG_C28) {
        ret = write_cap_reg(env, regid - UC_ARM64_REG_C0, (uc_cheri_cap *)value);
    } else 
#endif
    if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
        arm_set_xreg(env, regid - UC_ARM64_REG_X0, *(uint64_t *)value);
    } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
        uint64_t old_val = arm_get_xreg(env, regid - UC_ARM64_REG_W0);
        uint64_t new_val = (old_val & ~0xffffffffLL) | (*(uint32_t *)value & 0xffffffff);
        arm_set_xreg(env, regid - UC_ARM64_REG_W0, new_val);
    } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) {
        float64 *src = (float64 *)value;
        uint32_t reg_index = regid - UC_ARM64_REG_Q0;
        env->vfp.zregs[reg_index].d[0] = src[0];
        env->vfp.zregs[reg_index].d[1] = src[1];
    } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
        env->vfp.zregs[regid - UC_ARM64_REG_D0].d[0] = *(float64 *)value;
    } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
        WRITE_DWORD(env->vfp.zregs[regid - UC_ARM64_REG_S0].d[0],
                    *(int32_t *)value);
    } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
        WRITE_WORD(env->vfp.zregs[regid - UC_ARM64_REG_H0].d[0],
                   *(int16_t *)value);
    } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
        WRITE_BYTE_L(env->vfp.zregs[regid - UC_ARM64_REG_B0].d[0],
                     *(int8_t *)value);
    } else if (regid >= UC_ARM64_REG_ELR_EL0 && regid <= UC_ARM64_REG_ELR_EL3) {
        set_aarch_reg_value(&env->elr_el[regid - UC_ARM64_REG_ELR_EL0], *(uint64_t *)value);
    } else if (regid >= UC_ARM64_REG_SP_EL0 && regid <= UC_ARM64_REG_SP_EL3) {
        set_aarch_reg_value(&env->sp_el[regid - UC_ARM64_REG_SP_EL0], *(uint64_t *)value);
    } else if (regid >= UC_ARM64_REG_ESR_EL0 && regid <= UC_ARM64_REG_ESR_EL3) {
        env->cp15.esr_el[regid - UC_ARM64_REG_ESR_EL0] = *(uint64_t *)value;
    } else if (regid >= UC_ARM64_REG_FAR_EL0 && regid <= UC_ARM64_REG_FAR_EL3) {
        env->cp15.far_el[regid - UC_ARM64_REG_FAR_EL0] = *(uint64_t *)value;
    } else if (regid >= UC_ARM64_REG_VBAR_EL0 &&
               regid <= UC_ARM64_REG_VBAR_EL3) {
        set_aarch_reg_value(&env->cp15.vbar_el[regid - UC_ARM64_REG_VBAR_EL0], *(uint64_t *)value);
    } else {
        switch (regid) {
        default:
            break;
        case UC_ARM64_REG_CPACR_EL1:
            env->cp15.cpacr_el1 = *(uint32_t *)value;
            break;
        case UC_ARM64_REG_TPIDR_EL0:
            set_aarch_reg_value(&env->cp15.tpidr_el[0], *(uint64_t *)value);
            break;
        case UC_ARM64_REG_TPIDRRO_EL0:
            set_aarch_reg_value(&env->cp15.tpidrro_el[0], *(uint64_t *)value);
            break;
        case UC_ARM64_REG_TPIDR_EL1:
            set_aarch_reg_value(&env->cp15.tpidr_el[1], *(uint64_t *)value);
            break;
        case UC_ARM64_REG_X29:
            arm_set_xreg(env, 29, *(uint64_t *)value);
            break;
        case UC_ARM64_REG_X30:
            arm_set_xreg(env, 30, *(uint64_t *)value);
            break;
        case UC_ARM64_REG_PC:
#ifdef TARGET_CHERI
            set_max_perms_capability(&env->pc.cap, *(uint64_t *)value);
#else
            set_aarch_reg_value(&env->pc, *(uint64_t *)value);
#endif
            break;
        case UC_ARM64_REG_SP:
            arm_set_xreg(env, 31, *(uint64_t *)value);
            break;
        case UC_ARM64_REG_NZCV:
            cpsr_write(env, *(uint32_t *)value, CPSR_NZCV, CPSRWriteRaw);
            break;
        case UC_ARM64_REG_PSTATE:
            pstate_write(env, *(uint32_t *)value);
            break;
        case UC_ARM64_REG_TTBR0_EL1:
            env->cp15.ttbr0_el[1] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_TTBR1_EL1:
            env->cp15.ttbr1_el[1] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_PAR_EL1:
            env->cp15.par_el[1] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_MAIR_EL1:
            env->cp15.mair_el[1] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_CP_REG:
            ret = write_cp_reg(env, (uc_arm64_cp_reg *)value);
            break;
        case UC_ARM64_REG_FPCR:
            vfp_set_fpcr(env, *(uint32_t *)value);
            break;
        case UC_ARM64_REG_FPSR:
            vfp_set_fpsr(env, *(uint32_t *)value);
            break;
        }
    }

    return ret;
}

int arm64_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                   int count)
{
    CPUARMState *env = &(ARM_CPU(uc->cpu)->env);
    int i;
    uc_err err;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        err = reg_read(env, regid, value);
        if (err) {
            return err;
        }
    }

    return UC_ERR_OK;
}

int arm64_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                    int count)
{
    CPUARMState *env = &(ARM_CPU(uc->cpu)->env);
    int i;
    uc_err err;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        err = reg_write(env, regid, value);
        if (err) {
            return err;
        }
        if (regid == UC_ARM64_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }

    return UC_ERR_OK;
}

DEFAULT_VISIBILITY
#ifdef TARGET_WORDS_BIGENDIAN
int arm64eb_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                             void **vals, int count)
#else
#ifdef TARGET_CHERI
int arm64c_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                           void **vals, int count)
#else
int arm64_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                           void **vals, int count)
#endif
#endif
{
    CPUARMState *env = (CPUARMState *)ctx->data;
    int i;
    uc_err err;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        err = reg_read(env, regid, value);
        if (err) {
            return err;
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_WORDS_BIGENDIAN
int arm64eb_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                              void *const *vals, int count)
#else
#ifdef TARGET_CHERI
int arm64c_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                            void *const *vals, int count)
#else
int arm64_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                            void *const *vals, int count)
#endif
#endif
{
    CPUARMState *env = (CPUARMState *)ctx->data;
    int i;
    uc_err err;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        err = reg_write(env, regid, value);
        if (err) {
            return err;
        }
    }

    return 0;
}

static int arm64_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    ARMCPU *cpu;

    cpu = cpu_aarch64_init(uc);
    if (cpu == NULL) {
        return -1;
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_CHERI
void arm64c_uc_init(struct uc_struct *uc)
#else
void arm64_uc_init(struct uc_struct *uc)
#endif
{
    uc->reg_read = arm64_reg_read;
    uc->reg_write = arm64_reg_write;
    uc->reg_reset = arm64_reg_reset;
    uc->set_pc = arm64_set_pc;
    uc->get_pc = arm64_get_pc;
    uc->release = arm64_release;
    // XXXR3: todo, query mode, A64 or C64
    // uc->query = arm64_query;
    uc->cpus_init = arm64_cpus_init;
    uc->cpu_context_size = offsetof(CPUARMState, cpu_watchpoint);
    uc_common_init(uc);
}
