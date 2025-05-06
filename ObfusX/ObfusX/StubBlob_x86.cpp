#include "StubBlob_x86.h"

const unsigned char g_stubCode_x86[] = {
    // --- Save registers ---
    0x60,                               // pushad
    0x9C,                               // pushfd

    // --- Get base address (GetModuleHandle(NULL)) ---
    0xE8, 0x00, 0x00, 0x00, 0x00,       // call $+5 (push next instr addr)
    0x5B,                               // pop ebx  => ebx = base

    // --- Anti-Debug: IsDebuggerPresent ---
    0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, // mov eax, fs:[0x30]   ; PEB
    0x8A, 0x40, 0x02,                   // mov al, [eax+2]      ; BeingDebugged
    0x84, 0xC0,                         // test al, al
    0x74, 0x05,                         // jz skipExit
    0x6A, 0x01,                         // push 1
    0xFF, 0x15, 0xAA, 0xAA, 0xAA, 0xAA, // call [ExitProcess]
    // skipExit:

    // --- VirtualProtect(.text) ---
    0x68, 0xCC, 0xCC, 0xCC, 0xCC,       // push dwSize (.text size)
    0x68, 0xBB, 0xBB, 0xBB, 0xBB,       // push lpAddress (.text RVA)
    0x6A, 0x40,                         // push PAGE_EXECUTE_READWRITE
    0x8D, 0x4C, 0x24, 0x08,             // lea ecx, [esp+8]
    0x51,                               // push ecx
    0xFF, 0x15, 0xBB, 0xBB, 0xBB, 0xBB, // call [VirtualProtect]

    // --- XOR decode loop (.text) ---
    0x8B, 0x1C, 0x24,                   // mov ebx, [esp] ; .text address
    0xB9, 0xCC, 0xCC, 0xCC, 0xCC,       // mov ecx, dwSize
    0xB8, 0x5A, 0x00, 0x00, 0x00,       // mov eax, 0x5A
    // decodeLoop:
    0x30, 0x03,                         // xor [ebx], al
    0x43,                               // inc ebx
    0xE2, 0xFB,                         // loop decodeLoop

    // --- Restore registers ---
    0x9D,                               // popfd
    0x61,                               // popad

    // --- Jump to original EntryPoint ---
    0xB8, 0xAA, 0xAA, 0xAA, 0xAA,       // mov eax, EntryPoint
    0xFF, 0xE0                          // jmp eax
};

const unsigned int g_stubSize_x86 = sizeof(g_stubCode_x86);
