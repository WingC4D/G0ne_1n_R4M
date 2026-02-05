#pragma once
#include <iostream>
#include <vector>
#include <Windows.h>
#include <winternl.h>
#ifndef HUINT
#define LOCAL_PROCESS_HANDLE reinterpret_cast<HANDLE>(-1)
#define LOCAL_THREAD_HANDLE  reinterpret_cast<HANDLE>(-2)

	#ifdef _M_IX86
	typedef unsigned long	   hUINT
	#define hUINT
	#define TRAMPOLINE_SIZE 0x07
	#elifdef _M_X64
	typedef unsigned long long hUINT;
	#define HUINT
	#define TRAMPOLINE_SIZE 0x0D
	#endif
#endif
#ifdef  __cplusplus
namespace ct {
	constexpr hUINT GenerateSeed()
	{
		return '0' * -40276 +
			__TIME__[7] * 1 +
			__TIME__[6] * 10 +
			__TIME__[4] * 60 +
			__TIME__[3] * 600 +
			__TIME__[1] * 3600 +
			__TIME__[0] * 36000;
	}

	constexpr auto g_Seed = GenerateSeed();

	constexpr hUINT ctGenerateHashW
	(
		_In_ LPCWSTR lpStringToHash
	) {
		WORD  wChar;
		hUINT uiHash = NULL,
			uiSeed = g_Seed;
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
	constexpr hUINT ctGenerateHashA
	(
		_In_ LPCSTR lpStringToHash
	) {
		CHAR  cChar;
		hUINT uiHash = NULL,
			uiSeed = g_Seed;
		while ((cChar = *lpStringToHash++) != NULL)
		{
			uiHash += cChar;
			uiHash += uiHash << (uiSeed & 0x3F);
			uiHash ^= uiHash >> 6;
		}

		uiHash += uiHash << 3;
		uiHash ^= uiHash >> 11;
		uiHash += uiHash << 15;

		return uiHash;
	};
	constexpr hUINT nt_dll = ctGenerateHashW(L"ntdll.dll");
	constexpr hUINT nt_query_info_proc = ctGenerateHashA("NtQueryInformationProcess");
	constexpr hUINT nt_query_sys_info = ctGenerateHashA("NtQuerySystemInformation");
}
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)
(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess)
(
	IN              HANDLE           hProcessHandle,
	IN              PROCESSINFOCLASS process_information_class_t,
	OUT          PVOID            pProcessInformation,
	IN              ULONG            ulProcessInfoLength,
	OUT OPTIONAL PULONG           pulReturnLength
	);

typedef struct MODULE_DATA
{
	LPBYTE				  lpModuleBaseAddr;
	LPDWORD				  lpFunctionsRVA_arr,
		lpNamesRVA_arr;
	LPWORD				  lpOrdsRVA_arr;
	PLDR_DATA_TABLE_ENTRY pModuleLDR;
	DWORD				  dwNumberOfNames,
						  dwNumberOfFunctions;
	DWORD64 ullImageSize;
}*MODULE_DATA_PTR;
#endif

typedef class Scanner
{
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
	MODULE_DATA_PTR		  pModuleData;
	PPEB	pTargetPEB;
	HANDLE	hProcess,
			hThread,
			hHeap;
	
	DWORD	dwTargetPID,
			dwTargetTID;

	PSYSTEM_PROCESS_INFORMATION pSystemProcInfo;

	Scanner
	(
		_In_ HANDLE hTargetProcess
	);

	hUINT getFunctionSize
	(
		LPVOID lpFunctionAddress
	);

	HMODULE getLocalModuleHandleByFunction
	(
		LPVOID lpFunctionAddress
	);

	scannerErrorCode getLastError() const;

	BOOLEAN isThreadInProcess
	(
		_In_ HANDLE hCandidateThread
	);

	scannerErrorCode mapModuleData(PLDR_DATA_TABLE_ENTRY lpModuleLDR);

private:
	

	DWORD				  dwFuncSize;
	WORD				  wTargetOrdinal;
	BOOLEAN				  bIsLocal;
	scannerErrorCode	  ecStatus;

	HMODULE getModuleHandleH
	(
		IN     hUINT uiHashedModuleName
	);

	WORD getFuncOrdinal
	(
		IN       LPVOID  lpFunction
	);

	FARPROC getProcAddressH
	(
		IN       HMODULE hModule,
		IN       hUINT   uiHashedName
	);

	PPEB getLocalPeb
	(
		IN     void
	);

	BOOLEAN validateLocalPEB
	(
		IN     void
	);
	PIMAGE_OPTIONAL_HEADER get_image_optional_headers(LPBYTE pImageBase);
	PIMAGE_EXPORT_DIRECTORY getImageExportDirectory(LPBYTE pImageBase);
	BOOLEAN isThreadLocal(HANDLE hThread);
} *PScanner;

