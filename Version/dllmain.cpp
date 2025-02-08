#include "Hijack.h"
#include <detours.h>
#include <wchar.h>
#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <algorithm>

typedef HMODULE(WINAPI* pLoadLibraryExW)(
    LPCWSTR lpLibFileName,
    HANDLE hFile,
    DWORD  dwFlags
    );
pLoadLibraryExW rawLoadLibraryExW;

static void ModifyDll(const std::wstring& path) {
    std::fstream dllFile(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!dllFile.is_open()) {
        //std::wcerr << L"无法打开文件: " << path << std::endl;
        return;
    }
    // 禁用动态基址
    dllFile.seekp(326, std::ios::beg);
    char zeroByte = 0x00;
    dllFile.write(&zeroByte, 1);

    dllFile.seekg(0, std::ios::end);
    size_t size = dllFile.tellg();
    dllFile.seekg(0, std::ios::beg);
    char* buffer = new char[size];
    dllFile.read(buffer, size);

    char searchBytes[] = {
        0x55,                         // push ebp
        0x8B, 0xEC,                   // mov ebp, esp
        0x8B, 0x4D, 0x08,             // mov ecx, dword ptr ss:[ebp+0x08]
        0x85, 0xC9,                   // test ecx, ecx
        0x74, 0x13,                   // je short 0x13
        0xFF, 0x75, 0x10,             // push dword ptr ss:[ebp+0x10]
        0xFF, 0x75, 0x0C,             // push dword ptr ss:[ebp+0x0C]
        0xE8, 0xFB, 0x08, 0x00, 0x00, // call 0x0000C0F0
        0x84, 0xC0,                   // test al, al
        0x74, 0x04,                   // je short 0x04
        0xB0, 0x01,                   // mov al, 0x01
        0x5D,                         // pop ebp
        0xC3,                         // ret
        0x32, 0xC0,                   // xor al, al
        0x5D,                         // pop ebp
        0xC3                          // ret
    };
    size_t searchSize = sizeof(searchBytes) / sizeof(char);

    char mask[] = {
        1,
        1, 1,
        1, 1, 1,
        1, 1,
        1, 1,
        1, 1, 1,
        1, 1, 1,
        1, 0, 0, 0, 0,
        1, 1,
        1, 1,
        1, 1,
        1,
        1,
        1, 1,
        1,
        1
    };

    char newBytes[] = {
        0x55,                          // push ebp
        0x8B, 0xEC,                    // mov ebp, esp
        0x8B, 0x4D, 0x08,              // mov ecx, dword ptr ss:[ebp+0x08]
        0x85, 0xC9,                    // test ecx, ecx
        0xEB, 0x13,                    // jmp short 0x13 <===== Force Jump
        0xFF, 0x75, 0x10,              // push dword ptr ss:[ebp+0x10]
        0xFF, 0x75, 0x0C,              // push dword ptr ss:[ebp+0x0C]
        0xE8, 0x3B, 0x0F, 0x00, 0x00,  // call 0x0000C0F0
        0x84, 0xC0,                    // test al, al
        0x74, 0x04,                    // je short 0x04
        0xB0, 0x01,                    // mov al, 0x01
        0x5D,                          // pop ebp
        0xC3,                          // ret
        0xB0, 0x01,                    // mov al, 0x01   <===== Force bypass
        0x5D,                          // pop ebp
        0xC3                           // ret
    };
    size_t newSize = sizeof(newBytes) / sizeof(char);

    for (size_t i = 0; i <= size - searchSize; ++i) { 
        bool match = true;
        for (size_t j = 0; j < searchSize; ++j) {
            if (mask[j] == 1 && buffer[i + j] != searchBytes[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            std::copy(newBytes, newBytes + newSize, buffer + i);

            dllFile.seekp(i, std::ios::beg);
            dllFile.write(newBytes, newSize);
            //std::wcout << L"字节序列已成功替换。" << std::endl;
            break;
        }
    }

	delete[] buffer;
	dllFile.close();
}

static HMODULE WINAPI newLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD  dwFlags) {
    //wprintf(L"Load DLL: %s\n", lpLibFileName);
    std::wstring libFileName(lpLibFileName);
    if (libFileName.find(L"appdata\\local\\temp") != std::wstring::npos) {
        //wprintf(L"Modify DLL: %s\n", lpLibFileName);
        ModifyDll(libFileName);
        //wprintf(L"Done.\n");
    }
    return rawLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

static VOID StartHook() {
    rawLoadLibraryExW = (pLoadLibraryExW)GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "LoadLibraryExW");

    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)rawLoadLibraryExW, newLoadLibraryExW);
    DetourTransactionCommit();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        /*
        if (AllocConsole()) {
            FILE* pFile;
            freopen_s(&pFile, "CONOUT$", "w", stdout);
            freopen_s(&pFile, "CONOUT$", "w", stderr);
        }
        */
        StartHook();
        CreateHijack();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        FreeHijack();
        /*
        fclose(stdout);
        fclose(stderr);
        FreeConsole();
        */
        break;
    }
    return TRUE;
}
