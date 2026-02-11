#pragma once
#include <iostream>
#include <vector>
#include <memory>
#include <Windows.h>
#include <winternl.h>
#ifndef HUINT
#define LOCAL_PROCESS_HANDLE reinterpret_cast<HANDLE>(-1)
#define LOCAL_THREAD_HANDLE  reinterpret_cast<HANDLE>(-2)

	#ifdef _M_IX86
	typedef unsigned long	   hkUINT
	#define HKUINT
	#define TRAMPOLINE_SIZE 0x05
	#elifdef _M_X64
	typedef unsigned long long hkUINT;
	#define HKUINT
	#define TRAMPOLINE_SIZE 0x0D
	#endif
#endif
#ifdef  __cplusplus
namespace ct {
	constexpr hkUINT GenerateSeed() {
		return '0' * -40276 +
			__TIME__[7] * 1 +
			__TIME__[6] * 10 +
			__TIME__[4] * 60 +
			__TIME__[3] * 600 +
			__TIME__[1] * 3600 +
			__TIME__[0] * 36000;
	}

	constexpr auto g_Seed = GenerateSeed();

	constexpr hkUINT ctGenerateHashW(_In_ LPCWSTR lpStringToHash) {
		WORD   wChar;
		hkUINT uiHash = NULL,
			   uiSeed = g_Seed;
		while ((wChar = *lpStringToHash++) != NULL) {
			uiHash += wChar;
			uiHash += uiHash << (uiSeed & 0x3F);
			uiHash ^= uiHash >> 6;
		}

		uiHash += uiHash << 3;
		uiHash ^= uiHash >> 11;
		uiHash += uiHash << 15;

		return uiHash;
	};
	constexpr hkUINT ctGenerateHashA(_In_ LPCSTR lpStringToHash) {
		CHAR   cChar;
		hkUINT uiHash = NULL,
			   uiSeed = g_Seed;
		while ((cChar = *lpStringToHash++) != NULL) {
			uiHash += cChar;
			uiHash += uiHash << (uiSeed & 0x3F);
			uiHash ^= uiHash >> 6;
		}

		uiHash += uiHash << 3;
		uiHash ^= uiHash >> 11;
		uiHash += uiHash << 15;

		return uiHash;
	};
	constexpr hkUINT nt_dll			    = ctGenerateHashW(L"ntdll.dll");
	constexpr hkUINT nt_query_info_proc = ctGenerateHashA("NtQueryInformationProcess");
	constexpr hkUINT nt_query_sys_info  = ctGenerateHashA("NtQuerySystemInformation");
}
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess) (
	_In_	  HANDLE           hProcessHandle,
	_In_	  PROCESSINFOCLASS process_information_class_t,
	_Out_	  PVOID			   pProcessInformation,
	_In_      ULONG			   ulProcessInfoLength,
	_Out_opt_ PULONG		   pulReturnLength
);
#endif

typedef struct MODULE_DATA {
	LPBYTE				  lpModuleBaseAddr;
	LPDWORD				  lpFunctionsRVA_arr,
						  lpNamesRVA_arr;
	LPWORD				  lpOrdsRVA_arr;
	PLDR_DATA_TABLE_ENTRY pModuleLDR;
	DWORD				  dwNumberOfNames,
						  dwNumberOfFunctions;
	DWORD64				  ullImageSize;
}*MODULE_DATA_PTR;

typedef class Scanner {
public:
	enum scannerErrorCode: UCHAR {
		success,
		noInput,
		badProcessHandle,
		failedToGetHeapHandle,
		invalidHandle,
		invalidDosHeader,
		invalidPeHeader,
		invalidOptionalHeader,
		emptyExportDirectory,
		failedToFindNtQuerySysInfo,
		failedToFindSysProcInfoSize,
		failedToFindSysProcInfo,
		failedToAllocateMemory,
		failedToFetchLocalPEB,
		failedToFindModule,
		failedToFindTargetFuncOrdinal,
		failedToGetExportDir,
		noProcessAttached,
		threadEnumerationFailed,
		threadIsNotInProcess,
		processEnumerationFailed,
		notBuiltYet

	};
	std::unique_ptr<MODULE_DATA> pModuleData;
	PPEB	pTargetPEB;
	HANDLE	hProcess,
			hThread,
			hHeap;
	DWORD	dwTargetPID,
			dwTargetTID;
	std::vector<BYTE>pSystemProcInfo;

	Scanner(_In_ HANDLE hTargetProcess);

	HMODULE getLocalModuleHandleByFunction(LPVOID lpFunctionAddress);

	scannerErrorCode getLastError(_In_ void) const;

	BOOLEAN isThreadInProcess(_In_ HANDLE hCandidateThread);

	scannerErrorCode mapModuleData(PLDR_DATA_TABLE_ENTRY lpModuleLDR);

private:
	DWORD				  dwFuncSize;
	WORD				  wTargetOrdinal;
	BOOLEAN				  bIsLocal;
	scannerErrorCode	  ecStatus;

	HMODULE getModuleHandleH(_In_ hkUINT uiHashedModuleName);

	WORD getFuncOrdinal(_In_ LPVOID lpFunction);

	FARPROC getProcAddressH(_In_ HMODULE hModule, _In_ hkUINT uiHashedName);

	PPEB getLocalPeb(_In_ void);

	BOOLEAN validateLocalPEB(_In_ void);

	PIMAGE_OPTIONAL_HEADER get_image_optional_headers(_In_ LPBYTE pImageBase);

	PIMAGE_EXPORT_DIRECTORY getImageExportDirectory(_In_ LPBYTE pImageBase);

	BOOLEAN isThreadLocal(_In_ HANDLE hThread);
} *PScanner;

