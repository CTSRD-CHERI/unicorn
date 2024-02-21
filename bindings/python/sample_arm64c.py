#!/usr/bin/env python
# Sample code for ARM64 C64 of Unicorn. Zhuo Ying Jiang Li <zyj20 [at] cl.cam.ac.uk>

from __future__ import print_function
from unicorn import *
from unicorn.arm64_const import *
from unicorn.cheri_const import *

# code to be emulated
# not memory-related instructions
# add w0, w0, 0x1
ARM64C_ADD_CODE = b"\x00\x04\x00\x11"

# capability arithmetic
# add c0, c1, #0x2
ARM64C_ADD_CAP_CODE = b"\x20\x08\x00\x02"

# load store integers
# str        w11, [c13], #0
# ldrb       w15, [c13], #0
ARM64C_MEM_CODE = b"\xab\x05\x00\xb8\xaf\x05\x40\x38"

# load store capabilities
# str c0, [csp, #0x10]
# ldr c1, [csp, #0x10]
ARM64C_MEM_CAP_CODE = b"\xe0\x07\x00\xc2\xe1\x07\x40\xc2"

# memory address where emulation starts
ADDRESS    = 0x10000

def print_capability(cap: tuple):
    print('{')
    print('    Address:     0x%x' % cap[0])
    print("    Base:        0x%x" % cap[1])
    print("    Top:         0x%x" % cap[2])
    print("    Permissions: 0x%x" % cap[5])
    print("    User Perms:  0x%x" % cap[4])
    print("    OType:       0x%x" % cap[6])
    print("    Tag:         0x%x" % cap[3])
    print('}')


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


def test_arm64c():
    print("Emulate ARM64 C64 code")
    try:
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM | UC_MODE_C64)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, ARM64C_ADD_CODE)

        # initialize machine registers
        mu.reg_write(UC_ARM64_REG_X0, 0x1)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing one instruction with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(ARM64C_ADD_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")
        print(">>> As little endian, X0 should be 0x2:")

        x0 = mu.reg_read(UC_ARM64_REG_X0)
        print(">>> X0 = 0x%x" % x0)

    except UcError as e:
        print("ERROR: %s" % e)

def test_arm64c_mem_cap():
    print('Emulate ARM64 C64 code (memory load and store caps)')
    try:
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM | UC_MODE_C64)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, ARM64C_MEM_CAP_CODE)

        # initialize machine registers
        mu.reg_write(UC_ARM64_REG_C0, (ADDRESS + 0x33, ADDRESS, ADDRESS + 0x100, 1, 0, 0, 0))
        mu.reg_write(UC_ARM64_REG_C1, (0, 0, 0, 0, 0, 0, 0))
        mu.reg_write(UC_ARM64_REG_CSP, (ADDRESS + 0x50, ADDRESS, ADDRESS + 0x100, 1, 0, UC_CHERI_PERM_LOAD | UC_CHERI_PERM_STORE | UC_CHERI_PERM_LOAD_CAP | UC_CHERI_PERM_STORE_CAP | UC_CHERI_PERM_STORE_LOCAL, 0))

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing one instruction with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(ARM64C_MEM_CAP_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")
        c0 = mu.reg_read(UC_ARM64_REG_C0)
        c1 = mu.reg_read(UC_ARM64_REG_C1)
        csp = mu.reg_read(UC_ARM64_REG_CSP)
        print(">>> C0 = ")
        print_capability(c0)
        print(">>> C1 = ")
        print_capability(c1)
        print(">>> CSP = ")
        print_capability(csp)

        print("Use uc_mem_read_cap to read capability at csp+0x10:")
        cap = mu.mem_read_cap(csp[0] + 0x10)
        print_capability(cap)
    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == '__main__':
    test_arm64c()
    print("=" * 26)
    test_arm64c_mem_cap()
