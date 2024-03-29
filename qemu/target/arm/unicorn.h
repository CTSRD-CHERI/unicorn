/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_ARM_H
#define UC_QEMU_TARGET_ARM_H

// functions to read & write registers
int arm_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                 int count);
int arm_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                  int count);
int arm64_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                   int count);
int arm64_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                    int count);

int arm_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                         void **vals, int count);
int arm_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                          void *const *vals, int count);
int arm64_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                           void **vals, int count);
int arm64_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                            void *const *vals, int count);
int arm64c_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                            void **vals, int count);
int arm64c_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                             void *const *vals, int count);

void arm_reg_reset(struct uc_struct *uc);
void arm64_reg_reset(struct uc_struct *uc);

void arm_uc_init(struct uc_struct *uc);

int arm64c_mem_read_cap(struct uc_struct *uc, uint64_t address,
                        uc_cheri_cap *cap);
int arm64c_mem_write_cap(struct uc_struct *uc, uint64_t address,
                         const uc_cheri_cap *cap);

void arm64_uc_init(struct uc_struct *uc);
void arm64c_uc_init(struct uc_struct *uc);
#endif
