#include "Hijack.h"
#include <detours.h>
#include <wchar.h>
#include <string>
#include <fstream>
#include <iostream>
#include <vector>

typedef HMODULE(WINAPI* pLoadLibraryExW)(
    LPCWSTR lpLibFileName,
    HANDLE hFile,
    DWORD  dwFlags
    );
pLoadLibraryExW rawLoadLibraryExW;

void ModifyDll(const std::wstring& path) {
    std::fstream dllFile;
    dllFile.open(path, std::ios::in | std::ios::out | std::ios::binary);
    if (dllFile.is_open()) {
        dllFile.seekp(0x0000B7A0, std::ios::beg);
        char newBytes[] = {
            0x55,                          // push ebp
            0x8B, 0xEC,                    // mov ebp, esp
            0x8B, 0x4D, 0x08,              // mov ecx, dword ptr ss:[ebp+0x08]
            0x85, 0xC9,					   // test ecx, ecx
            0xEB, 0x13, 				   // jmp short 0x13 <===== Force Jump
            0xFF, 0x75, 0x10,			   // push dword ptr ss:[ebp+0x10]
            0xFF, 0x75, 0x0C,			   // push dword ptr ss:[ebp+0x0C]
            0xE8, 0x3B, 0x0F, 0x00, 0x00,  // call 0x0000C0F0
            0x84, 0xC0,					   // test al, al
            0x74, 0x04,					   // je short 0x04
            0xB0, 0x01,					   // mov al, 0x01
            0x5D,						   // pop ebp
            0xC3,						   // ret
            0xB0, 0x01,					   // mov al, 0x01   <===== Force bypass
            0x5D,						   // pop ebp
            0xC3 						   // ret
        };
        dllFile.write(newBytes, sizeof(newBytes));
        dllFile.close();
    }
}

HMODULE WINAPI newLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD  dwFlags) {
    wprintf(L"Load DLL: %s\n", lpLibFileName);
    std::wstring libFileName(lpLibFileName);
    if (libFileName.find(L"appdata\\local\\temp") != std::wstring::npos) {
        //wprintf(L"Modify DLL: %s\n", lpLibFileName);
        ModifyDll(libFileName);
        //wprintf(L"Done.\n");
    }
    return rawLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

VOID StartHook() {
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
