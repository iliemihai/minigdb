#ifndef REGISTERS_H__
#define REGISTERS_H__

#include <sys.user.h>
#include <algorithm>

namesapce minidbg{
    enum class req{
        rax, rbx, rcx, rdx,
        rdi, rsi, rbp, rsp,
        r8, r9, r10, r11,
        r12, r13, r14, r15,
        rip, rflags, cs,
        orig_rax, fs_base,
        gs_base,
        fs, gs, ss, ds, es
    };

    static constexpr std::size_t n_registers = 27;

    struct req_descriptor{
        req r;
        int dwarf_r;
        std::string name;
    };
}

#endif