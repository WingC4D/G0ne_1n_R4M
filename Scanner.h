#pragma once
#include <iostream>
#include <format>
#include <vector>
#include <Windows.h>
#include <winternl.h>
#ifndef hUINT
	#define LOCAL_PROCESS_HANDLE reinterpret_cast<HANDLE>(-1)
	#define LOCAL_THREAD_HANDLE  reinterpret_cast<HANDLE>(-2)

	#ifdef _M_X64
		#define hUINT
		
		typedef unsigned long long hkUINT;

		constexpr hkUINT PAGE_SIZE		 = 0x10000,
						 MAX_ITERATIONS  = 0x8000;
		constexpr BYTE   TRAMPOLINE_SIZE = 0x0D;
		#define MAX_INSTRUCTION_SIZE 0x0F
	#else
		#ifdef _M_IX86 
			typedef unsigned long	   hkUINT
			#define hkUINT
			#define MAX_ITERATIONS 0x8000
			#define PAGE_SIZE	   0x10000
			#define TRAMPOLINE_SIZE 0x07
			#define MAX_INSTRUCTION_SIZE 0x0F
		#endif
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
		WORD   wChar = NULL;
		hkUINT uiHash = NULL;
		hkUINT uiSeed = g_Seed;
		while ((wChar = *lpStringToHash++) != NULL)
		{
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
		CHAR   cChar = NULL;
		hkUINT uiHash = NULL;
		hkUINT uiSeed = g_Seed;
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
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation) (
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess) (
	IN              HANDLE           hProcessHandle,
	IN              PROCESSINFOCLASS process_information_class_t,
	   OUT          PVOID            pProcessInformation,
	IN              ULONG            ulProcessInfoLength,
	OUT OPTIONAL    PULONG           pulReturnLength
);

typedef struct MODULE_DATA {
	LPBYTE				  lpModuleBaseAddr;
	LPDWORD				  lpFunctionsRVA_arr,
						  lpNamesRVA_arr;
	LPWORD				  lpOrdsRVA_arr;
	PLDR_DATA_TABLE_ENTRY pModuleLDR;
	DWORD				  ullImageSize;
	DWORD				  dwNumberOfNames,
						  dwNumberOfFunctions;
}*MODULE_DATA_PTR;
#endif

typedef class Scanner {
public:
	enum scannerErrorCode : UCHAR {
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
private:
	WORD				  wTargetOrdinal = NULL;
	BOOLEAN				  bIsLocal = FALSE;
	scannerErrorCode	  ecStatus = success;
	std::vector<BYTE>	  pSystemProcInfo;

	HMODULE getModuleHandleH(_In_ hkUINT uiHashedModuleName);

	WORD getFuncOrdinal(_In_ LPVOID  lpFunction);

	FARPROC getProcAddressH(_In_ HMODULE hModule, _In_ hkUINT  uiHashedName);


	PIMAGE_EXPORT_DIRECTORY getImageExportDirectory(LPBYTE pImageBase);

	BOOLEAN isThreadLocal(HANDLE hThread);

public:
	PPEB getLocalPeb(_In_ void);

	BOOLEAN validateLocalPEB(_In_ void);

	PIMAGE_OPTIONAL_HEADER get_image_optional_headers(LPBYTE pImageBase);

	std::unique_ptr<MODULE_DATA> pModuleData = std::unique_ptr<MODULE_DATA>();
	HANDLE hHeap = GetProcessHeap(),
		   hProcess = INVALID_HANDLE_VALUE,
		   hThread;
	PPEB   pTargetPEB = getLocalPeb();
	DWORD  dwTargetPID  = GetCurrentProcessId(),
		   dwTargetTID;

	static LPVOID get_adjacent_memory_forward_i32bit(HMODULE hModule, DWORD dwModuleSize);

	static LPVOID get_adjacent_memory_backward_i32bit(HMODULE hModule);

	HMODULE get_local_module_handle_by_function(_In_ LPVOID lpFunctionAddress);

	scannerErrorCode getLastError() const;

	BOOLEAN isThreadInProcess(_In_ HANDLE hCandidateThread);

	scannerErrorCode mapModuleData(_In_ PLDR_DATA_TABLE_ENTRY lpModuleLDR);


} *PScanner;

