#include "StubVM.h"
#include "Crypto.h"
#include "VMInterpreter.h"
#include <vector>
#include <cstdint>
#include <iostream>
#include <Windows.h>

std::vector<uint8_t> BuildStubVM(const std::vector<uint8_t>& encryptedBytecode, bool is64bit) {
    // [1] 안티디버깅 (간단한 check만 포함)
    if (IsDebuggerPresent()) {
        MessageBoxA(NULL, "Debugger detected!", "ObfusX", MB_ICONERROR);
        ExitProcess(1);
    }

    // [2] 복호화
    std::vector<uint8_t> decrypted = encryptedBytecode;
    DecryptBytecode(decrypted);

    // [3] VMInterpreter 실행
    std::cout << "[*] Executing ObfusX Stub...\n";
    VMInterpreter vm(decrypted);
    vm.run();

    // [4] 더미 stub code
    return std::vector<uint8_t>({ 0xC3 }); // ret
}
