#include "StubBlob_x64.h"

const unsigned char g_stubCode_x64[] = {
    0x50,                               // push rax
    0x53,                               // push rbx
    0x51,                               // push rcx
    0x52,                               // push rdx
    0x55,                               // push rbp
    0x56,                               // push rsi
    0x57,                               // push rdi
    0x41, 0x50,                         // push r8
    0x41, 0x51,                         // push r9
    0x41, 0x52,                         // push r10
    0x41, 0x53,                         // push r11
    0x41, 0x54,                         // push r12
    0x41, 0x55,                         // push r13
    0x41, 0x56,                         // push r14
    0x41, 0x57,                         // push r15

    0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, // lea rax, [rip+0]
    0x48, 0x83, 0xE8, 0x07,                   // sub rax, 7
    0x48, 0x89, 0xC3,                         // mov rbx, rax

    // xor decode .text (marker patched)
    0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0x00, 0x00, 0x00, 0x00, // mov rcx, text_size
    0x48, 0x8D, 0x83, 0xBB, 0xBB, 0xBB, 0xBB,                   // lea rax, [rbx+text_rva]
    0x80, 0x30, 0x5A,                                           // xor byte ptr [rax], 0x5A
    0x48, 0xFF, 0xC0,                                           // inc rax
    0xE2, 0xFA,                                                 // loop

    // xor decode .rdata (marker patched)
    0x48, 0xB9, 0xEE, 0xEE, 0xEE, 0xEE, 0x00, 0x00, 0x00, 0x00, // mov rcx, rdata_size
    0x48, 0x8D, 0x83, 0xDD, 0xDD, 0xDD, 0xDD,                   // lea rax, [rbx+rdata_rva]
    0x80, 0x30, 0x5A,                                           // xor byte ptr [rax], 0x5A
    0x48, 0xFF, 0xC0,                                           // inc rax
    0xE2, 0xFA,                                                 // loop

    // jmp to original EP (marker patched)
    0x48, 0x8D, 0x83, 0xAA, 0xAA, 0xAA, 0xAA,                   // lea rax, [rbx+ep_rva]
    0xFF, 0xE0                                                  // jmp rax
};

const unsigned int g_stubSize_x64 = sizeof(g_stubCode_x64);
