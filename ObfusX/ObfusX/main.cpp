#include <windows.h>
#include <iostream>
#include <filesystem>
#include <fcntl.h>
#include <io.h>
#include "Packer.h"

namespace fs = std::filesystem;

int wmain(int argc, wchar_t* argv[]) {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    std::wcout << L"[*] ObfusX - VMProtect-like Virtualization Packer\n\n";
    
    if (argc != 2) {
        std::wcout << L"[!] 사용법: 실행할 EXE 파일을 ObfusX.exe 위로 드래그하세요.\n";
        std::wcout << L"[!] 또는 명령줄에서: ObfusX.exe <target.exe>\n";
        std::wcout << L"\n[Enter] 키를 누르면 종료됩니다...";
        std::wcin.get();
        return 1;
    }

    std::wstring inputPath = fs::absolute(argv[1]);
    std::wcout << L"[DEBUG] 입력된 경로: " << inputPath << std::endl;

    if (!fs::exists(inputPath)) {
        std::wcerr << L"[!] 입력 파일을 찾을 수 없습니다: " << inputPath << std::endl;
        std::wcerr << L"[DEBUG] 현재 작업 디렉터리: " << fs::current_path() << std::endl;
        std::wcout << L"\n[Enter] 키를 누르면 종료됩니다...";
        std::wcin.get();
        return 1;
    }

    std::wstring outputPath = inputPath;
    size_t dot = outputPath.find_last_of(L'.');
    if (dot != std::wstring::npos)
        outputPath.insert(dot, L"_protected");
    else
        outputPath += L"_protected.exe";

    std::wcout << L"[DEBUG] 출력 파일 경로: " << outputPath << std::endl;

    if (!PackAndProtect(inputPath, outputPath)) {
        std::wcerr << L"[!] 패킹에 실패했습니다. 로그를 확인하세요.\n";
        std::wcout << L"\n[Enter] 키를 누르면 종료됩니다...";
        std::wcin.get();
        return 1;
    }

    std::wcout << L"\n[+] 가상화 패킹 완료! 결과 파일: " << outputPath << std::endl;
    std::wcout << L"\n[Enter] 키를 누르면 종료됩니다...";
    std::wcin.get();
    return 0;
}
