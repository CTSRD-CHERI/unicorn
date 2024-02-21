/*
    Unicorn Engine sample code to demonstrate how to emulate aarch64c code
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

#include <unicorn/unicorn.h>
#include <string.h>

// code to be emulated

// not memory-related instructions
// add w0, w0, 0x1
#define ARM64C_ADD_CODE "\x00\x04\x00\x11"

// capability arithmetic
// add c0, c1, #0x2
#define ARM64C_ADD_CAP_CODE "\x20\x08\x00\x02"

// load store integers
// str        w11, [c13], #0
// ldrb       w15, [c13], #0
#define ARM64C_MEM_CODE "\xab\x05\x00\xb8\xaf\x05\x40\x38"

// load store capabilities
// str c0, [csp, #0x10]
// ldr c1, [csp, #0x10]
#define ARM64C_MEM_CAP_CODE "\xe0\x07\x00\xc2\xe1\x07\x40\xc2"

// mrs        x2, tpidrro_el0
#define ARM64C_MRS_CODE "\x62\xd0\x3b\xd5"

// memory address where emulation starts
#define ADDRESS 0x10000

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size,
                       void *user_data)
{
    printf(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n",
           address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data)
{
    printf(">>> Tracing instruction at 0x%" PRIx64
           ", instruction size = 0x%x\n",
           address, size);
}

static void print_capability(uc_cheri_cap *cap)
{
    printf("{\n");
    printf("    Address:     0x%016" PRIx64 "\n", cap->address);
    printf("    Base:        0x%016" PRIx64 "\n", cap->base);
    printf("    Top:         0x%" PRIx64 "%016" PRIx64 " %s\n",
           (uint64_t)(cap->top >> 64), (uint64_t)cap->top,
           cap->top > UINT64_MAX ? " (greater than UINT64_MAX)" : "");
    printf("    Permissions: 0x%" PRIx32 "\n",
           cap->perms); // XXXR3: todo, pretty-print
    printf("    User Perms:  0x%" PRIx32 "\n", cap->uperms);
    printf("    OType:       0x%" PRIx32 "\n",
           cap->otype); // XXXR3: pretty-print
    printf("    Tag:         %d\n", cap->tag);
    printf("}\n");
}

static void test_arm64c_mem_fetch(void)
{
    uc_engine *uc;
    uc_err err;
    uint64_t x1, x0;
    uc_cheri_cap csp;
    // msr x0, CurrentEL
    unsigned char shellcode0[4] = {64, 66, 56, 213};
    // .text:00000000004002C0                 LDR             X1, [SP,#arg_0]
    unsigned char shellcode[4] = {0xE1, 0x03, 0x40, 0xF9};
    unsigned shellcode_address = 0x4002C0;
    uint64_t data_address = 0x10000000000000;

    printf("Emulate ARM64 C64 fetching stack data from high address %" PRIx64
           "\n",
           data_address);

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM | UC_MODE_C64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }
    uc_mem_map(uc, data_address, 0x30000, UC_PROT_ALL);
    uc_mem_map(uc, 0x400000, 0x1000, UC_PROT_ALL);
    csp.address = data_address;
    csp.base = data_address;
    csp.top = data_address + 0x100;
    csp.tag = 1;
    csp.uperms = UC_CHERI_UPERMS_ALL;
    csp.perms = UC_CHERI_PERM_STORE | UC_CHERI_PERM_LOAD;
    csp.otype = UC_CHERI_OTYPE_UNSEALED;
    uc_reg_write(uc, UC_ARM64_REG_CSP, &csp);
    uc_mem_write(uc, data_address, "\xc8\xc8\xc8\xc8\xc8\xc8\xc8\xc8", 8);
    uc_mem_write(uc, shellcode_address, shellcode0, 4);
    uc_mem_write(uc, shellcode_address + 4, shellcode, 4);

    err = uc_emu_start(uc, shellcode_address, shellcode_address + 4, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    x0 = 0;
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    printf(">>> x0(Exception Level)=%" PRIx64 "\n", x0 >> 2);

    err = uc_emu_start(uc, shellcode_address + 4, shellcode_address + 8, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    uc_reg_read(uc, UC_ARM64_REG_X1, &x1);

    printf(">>> X1 = 0x%" PRIx64 "\n", x1);

    uc_close(uc);
}

static void test_arm64c_mem_fetch_cap(void)
{
    uc_engine *uc;
    uc_err err;

    uc_cheri_cap c0, c1, csp;

    c0.address = ADDRESS + 0x33;
    c0.base = ADDRESS;
    c0.top = ADDRESS + 0x100;
    c0.tag = 1;
    c0.uperms = 0;
    c0.perms = 0;
    c0.otype = UC_CHERI_OTYPE_UNSEALED;

    memset(&c1, 0, sizeof(c1));

    csp.address = ADDRESS + 0x50; // 0x10 aligned
    csp.base = ADDRESS;
    csp.top = ADDRESS + 0x100;
    csp.tag = 1;
    csp.uperms = 0;
    csp.perms = UC_CHERI_PERM_LOAD | UC_CHERI_PERM_STORE |
                UC_CHERI_PERM_LOAD_CAP | UC_CHERI_PERM_STORE_CAP |
                UC_CHERI_PERM_STORE_LOCAL;
    csp.otype = UC_CHERI_OTYPE_UNSEALED;

    printf("Emulate ARM64 C64 code (store tagged capability to memory and use "
           "uc_mem_read_cap)\n");

    // Initialize emulator in ARM C64 mode
    err = uc_open(UC_ARCH_ARM64,
                  UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM | UC_MODE_C64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, ARM64C_MEM_CAP_CODE,
                 sizeof(ARM64C_MEM_CAP_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM64_REG_C0, &c0);
    uc_reg_write(uc, UC_ARM64_REG_C1, &c1);
    uc_reg_write(uc, UC_ARM64_REG_CSP, &csp);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM64C_MEM_CAP_CODE) - 1,
                       0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");
    uc_reg_read(uc, UC_ARM64_REG_C0, &c0);
    uc_reg_read(uc, UC_ARM64_REG_C1, &c1);
    uc_reg_read(uc, UC_ARM64_REG_CSP, &csp);
    printf(">>> C0 = ");
    print_capability(&c0);
    printf(">>> C1 = ");
    print_capability(&c1);
    printf(">>> CSP = ");
    print_capability(&csp);

    printf(">>> Read the capability stored at CSP+0x10:\n");
    uc_cheri_cap res;
    uc_mem_read_cap(uc, csp.address + 0x10, &res);
    print_capability(&res);

    uc_close(uc);
}

static void test_arm64c_mem_write_cap(void)
{
    uc_engine *uc;
    uc_err err;

    uc_cheri_cap c0, c1, csp;

    c0.address = ADDRESS + 0x33;
    c0.base = ADDRESS;
    c0.top = ADDRESS + 0x100;
    c0.tag = 1;
    c0.uperms = 0;
    c0.perms = 0;
    c0.otype = UC_CHERI_OTYPE_UNSEALED;

    memset(&c1, 0, sizeof(c1));

    csp.address = ADDRESS + 0x50; // 0x10 aligned
    csp.base = ADDRESS;
    csp.top = ADDRESS + 0x100;
    csp.tag = 1;
    csp.uperms = 0;
    csp.perms = UC_CHERI_PERM_LOAD | UC_CHERI_PERM_STORE |
                UC_CHERI_PERM_LOAD_CAP | UC_CHERI_PERM_STORE_CAP |
                UC_CHERI_PERM_STORE_LOCAL;
    csp.otype = UC_CHERI_OTYPE_UNSEALED;

    printf("Emulate ARM64 C64 code (use uc_mem_write_cap to store tagged "
           "capability to memory)\n");

    // Initialize emulator in ARM C64 mode
    err = uc_open(UC_ARCH_ARM64,
                  UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM | UC_MODE_C64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory, load cap from csp+0x10
    uc_mem_write(uc, ADDRESS, ARM64C_MEM_CAP_CODE + 4,
                 sizeof(ARM64C_MEM_CAP_CODE) - 4 - 1);

    // initialize machine registers
    uc_mem_write_cap(uc, csp.address + 0x10,
                     &c0); // (arbitrary) store a valid cap
    uc_reg_write(uc, UC_ARM64_REG_C1, &c1);
    uc_reg_write(uc, UC_ARM64_REG_CSP, &csp);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS,
                       ADDRESS + sizeof(ARM64C_MEM_CAP_CODE) - 4 - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(
        ">>> Emulation done. Below is the CPU context (valid cap we wrote)\n");
    uc_reg_read(uc, UC_ARM64_REG_C1, &c1);
    printf(">>> C1 = ");
    print_capability(&c1);

    uc_close(uc);
}

static void test_arm64c(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int64_t x0 = 0x1;

    printf("Emulate ARM64 C64 code (integer arithmetic operation)\n");

    // Initialize emulator in ARM C64 mode
    err = uc_open(UC_ARCH_ARM64,
                  UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM | UC_MODE_C64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, ARM64C_ADD_CODE, sizeof(ARM64C_ADD_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM64_REG_X0, &x0);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err =
        uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM64C_ADD_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");
    printf(">>> As little endian, X0 should be 0x2:\n");

    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    printf(">>> X0 = 0x%" PRIx64 "\n", x0);

    printf(">>> And C0 should be untagged:\n");
    uc_cheri_cap c0;
    uc_reg_read(uc, UC_ARM64_REG_C0, &c0);
    print_capability(&c0);

    uc_close(uc);
}

static void test_arm64c_cap(void)
{
    uc_engine *uc;
    uc_err err;

    uc_cheri_cap c0;
    uc_cheri_cap c1;

    memset(&c0, 0, sizeof(c0));
    c1.address = ADDRESS;
    c1.base = ADDRESS;
    c1.top = ADDRESS + 0x100;
    c1.tag = 1;
    c1.uperms = 0;
    c1.perms = 0;
    c1.otype = UC_CHERI_OTYPE_UNSEALED;

    printf("Emulate ARM64 C64 code (capability arithmetic operation)\n");

    // Initialize emulator in ARM C64 mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_C64 | UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, ARM64C_ADD_CAP_CODE,
                 sizeof(ARM64C_ADD_CAP_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM64_REG_C0, &c0);
    uc_reg_write(uc, UC_ARM64_REG_C1, &c1);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM64C_ADD_CAP_CODE) - 1,
                       0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");
    printf(">>> As little endian, C0 address should be 0x%x:\n", ADDRESS + 2);

    uc_reg_read(uc, UC_ARM64_REG_C0, &c0);
    printf(">>> C0 = ");
    print_capability(&c0);

    uc_close(uc);
}

static void test_arm64c_mem()
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int64_t x11 = 0x12345678;
    uc_cheri_cap c13; // this must be a valid capability
    int64_t x15 = 0x33;

    c13.address = ADDRESS + 0x10;
    c13.base = ADDRESS;
    c13.top = ADDRESS + 0x100;
    c13.tag = 1;
    c13.uperms = 0;
    c13.perms = UC_CHERI_PERM_LOAD | UC_CHERI_PERM_STORE;
    c13.otype = UC_CHERI_OTYPE_UNSEALED;

    printf("Emulate ARM64 C64 code (memory load and store)\n");

    // Initialize emulator in ARM C64 mode
    err = uc_open(UC_ARCH_ARM64,
                  UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM | UC_MODE_C64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, ARM64C_MEM_CODE, sizeof(ARM64C_MEM_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM64_REG_X11, &x11);
    uc_reg_write(uc, UC_ARM64_REG_C13, &c13);
    uc_reg_write(uc, UC_ARM64_REG_X15, &x15);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err =
        uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM64C_MEM_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");
    printf(">>> As little endian, X15 should be 0x78:\n");

    uc_reg_read(uc, UC_ARM64_REG_X15, &x15);
    printf(">>> X15 = 0x%" PRIx64 "\n", x15);

    printf(">>> And C15 should be untagged:\n");
    uc_cheri_cap c15;
    uc_reg_read(uc, UC_ARM64_REG_C15, &c15);
    print_capability(&c15);

    uc_close(uc);
}

static void test_arm64c_mem_cap()
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    uc_cheri_cap c0, c1, csp;

    c0.address = ADDRESS + 0x33;
    c0.base = ADDRESS;
    c0.top = ADDRESS + 0x100;
    c0.tag = 1;
    c0.uperms = 0;
    c0.perms = 0;
    c0.otype = UC_CHERI_OTYPE_UNSEALED;

    memset(&c1, 0, sizeof(c1));

    csp.address = ADDRESS + 0x50; // 0x10 aligned
    csp.base = ADDRESS;
    csp.top = ADDRESS + 0x100;
    csp.tag = 1;
    csp.uperms = 0;
    csp.perms = UC_CHERI_PERM_LOAD | UC_CHERI_PERM_STORE |
                UC_CHERI_PERM_LOAD_CAP | UC_CHERI_PERM_STORE_CAP |
                UC_CHERI_PERM_STORE_LOCAL;
    csp.otype = UC_CHERI_OTYPE_UNSEALED;

    printf("Emulate ARM64 C64 code (memory load and store caps)\n");

    // Initialize emulator in ARM C64 mode
    err = uc_open(UC_ARCH_ARM64,
                  UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM | UC_MODE_C64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, ARM64C_MEM_CAP_CODE,
                 sizeof(ARM64C_MEM_CAP_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM64_REG_C0, &c0);
    uc_reg_write(uc, UC_ARM64_REG_C1, &c1);
    uc_reg_write(uc, UC_ARM64_REG_CSP, &csp);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    uc_reg_read(uc, UC_ARM64_REG_C0, &c0);
    uc_reg_read(uc, UC_ARM64_REG_C1, &c1);
    uc_reg_read(uc, UC_ARM64_REG_CSP, &csp);
    printf("At the start of the emulation, the registers are: \n");
    printf(">>> C0 = ");
    print_capability(&c0);
    printf(">>> C1 = ");
    print_capability(&c1);
    printf(">>> CSP = ");
    print_capability(&csp);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM64C_MEM_CAP_CODE) - 1,
                       0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");
    uc_reg_read(uc, UC_ARM64_REG_C0, &c0);
    uc_reg_read(uc, UC_ARM64_REG_C1, &c1);
    uc_reg_read(uc, UC_ARM64_REG_CSP, &csp);
    printf(">>> C0 = ");
    print_capability(&c0);
    printf(">>> C1 = ");
    print_capability(&c1);
    printf(">>> CSP = ");
    print_capability(&csp);

    uc_close(uc);
}

static void test_update_pcc()
{
    uc_engine *uc;
    uc_err err;

    int64_t x0 = 0x1;
    uc_cheri_cap pcc;

    printf("Update PCC\n");

    // Initialize emulator in ARM C64 mode
    err = uc_open(UC_ARCH_ARM64,
                  UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM | UC_MODE_C64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, ARM64C_ADD_CODE, sizeof(ARM64C_ADD_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM64_REG_X0, &x0);

    uc_reg_read(uc, UC_ARM64_REG_PCC, &pcc);
    printf(">>> Old PPC is ");
    print_capability(&pcc);

    printf(">>> Restricting PCC\n");
    pcc.base = ADDRESS;
    pcc.top = ADDRESS + sizeof(ARM64C_ADD_CODE);
    pcc.perms = UC_CHERI_PERMS_ALL ^
                UC_CHERI_PERM_LOAD; // XXXR3: this doesn't raise any errors
    uc_reg_write(uc, UC_ARM64_REG_PCC, &pcc);
    printf(">>> Restricted PCC: ");
    uc_reg_read(uc, UC_ARM64_REG_PCC, &pcc);
    print_capability(&pcc);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err =
        uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM64C_ADD_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }
    uc_reg_read(uc, UC_ARM64_REG_PCC, &pcc);
    printf(">>> Now PPC is ");
    print_capability(&pcc);

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    test_arm64c_mem_fetch();

    printf("-------------------------\n");
    test_arm64c_mem_fetch_cap();

    printf("-------------------------\n");
    test_arm64c_mem_write_cap();

    printf("-------------------------\n");
    test_arm64c();

    printf("-------------------------\n");
    test_arm64c_cap();

    printf("-------------------------\n");
    test_arm64c_mem();

    printf("-------------------------\n");
    test_arm64c_mem_cap();

    printf("-------------------------\n");
    test_update_pcc();

    return 0;
}
