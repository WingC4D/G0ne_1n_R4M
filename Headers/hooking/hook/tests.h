#pragma once
#include <Windows.h>


typedef INT(WINAPI* fnMessageBoxA) (
    HWND   hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT   uType
);

typedef HANDLE(WINAPI* fnCreateFileW) (
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

inline fnMessageBoxA g_MessageBoxA;
inline fnCreateFileW g_CreateFileW;
int WINAPI HookedMessageBoxA(HWND hWindowHandle, LPCSTR lpText, LPCSTR lpHeader, UINT   uiType);

HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);