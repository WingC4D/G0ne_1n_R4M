#include "hooking/hook/tests.h"
#include <print>
int HookedMessageBoxA(HWND hWindowHandle, LPCSTR lpText, LPCSTR lpHeader, UINT uiType) {

    std::println(R"([+] Intercepted a MessageBoxA with hWnd:{:018p}, caption: "{:s}", text: "{:s}", and type: {:#010x}
)", (void*)hWindowHandle, lpHeader, lpText, uiType);


    return g_MessageBoxA(hWindowHandle, lpText, lpHeader, uiType);
}

HANDLE HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    std::wprintf(L"[+] Intercepted a CreateFileW with:\n"
                 L"\t1. file name:%ws\n"
                 L"\t2. desired access: %.8x\n"
                 L"\t3. share mode: %.8x\n"
                 L"\t4. security attributes at: %p\n",
        lpFileName, dwDesiredAccess, dwShareMode, (void*)lpSecurityAttributes);
    if (lpSecurityAttributes)
        if (lpSecurityAttributes->lpSecurityDescriptor)
            std::wprintf(L"\t\t[+] security descriptor at: %p\n", lpSecurityAttributes->lpSecurityDescriptor);
    std::wprintf(L"\t5. creation disposition: %.8x\n"
        L"\t6. flags: %.8x\n"
        L"\t7. template file: %p\n\n", 
        dwCreationDisposition, dwFlagsAndAttributes, (void*)hTemplateFile);
    return g_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}