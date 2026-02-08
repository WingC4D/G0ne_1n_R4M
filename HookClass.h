#pragma once
#include <algorithm>
#include <vector>
#include <iostream>
#include <deque>
#include <Windows.h>
#include <winternl.h>
#include  "Scanner.h"
#include "LDE.h"


#ifndef HUINT
#define LOCAL_PROCESS_HANDLE reinterpret_cast<HANDLE>(-1)
#define LOCAL_THREAD_HANDLE  reinterpret_cast<HANDLE>(-2)

#ifdef _M_IX86
typedef unsigned long	   hUINT
#define hkUINT
#define TRAMPOLINE_SIZE 0x07
#elifdef _M_X64
typedef unsigned long long hUINT;
#define HUINT
#define TRAMPOLINE_SIZE 0x0D
#endif
#endif

typedef struct HOOK_CONTEXT
{
	LPVOID  lpDetourFunc  = nullptr,
		   *lpOrgFuncAddr = nullptr,
		    lpTargetFunc  = nullptr;
	BYTE	cbHookLength  = NULL,
			bActive		  = FALSE,
			org_bytes_arr[TRAMPOLINE_SIZE  + 0x0F]	  = { },
			patched_bytes_arr[TRAMPOLINE_SIZE + 0x0F] = { };

} *LP_HOOK_CONTEXT;

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)
(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

typedef NTSTATUS (WINAPI *fnNtQueryInformationProcess)
(
	_In_	  HANDLE           hProcessHandle,
	_In_	  PROCESSINFOCLASS process_information_class_t,
	_Out_	  PVOID            pProcessInformation,
	_In_	  ULONG            ulProcessInfoLength,
	_Out_opt_ PULONG           pulReturnLength
);

class HookManager
{
public:
	PScanner	   pScanner;
	WORD		   wNumberOfHooks;
	std::deque<HOOK_CONTEXT>hkContexts;

	typedef enum ecManager : UCHAR {
		success,
		noInput,
		failedToConstructClass,
		failedToGetProcessHeap,
		failedToAllocateMemory,
		failedToCalculateFunctionSize,
		threadUpdateFailed,
		hookAttachFailed,
		commitingFailed,
		targetIsNotLocal,
		threadIsNotInProcess,
		failedToCalculateHookSize,
		wrong_input,
		hook_already_active,
		hook_already_inactive,
		notBuiltYet
	} *pecManager;

	HookManager
	(
		_In_ HANDLE hTargetProcess
	);

	ecManager initializeLocally
	(
		_In_ HANDLE hTargetThread
	);

	ecManager CreateLocalHook
	(
		_In_     LP_HOOK_CONTEXT pCandidateHookData_t,
		_Out_	 LPWORD		     lpHookID
	);

	ecManager attachToThread
	(
		HANDLE hThread
	);

static	LPBYTE generate_nop
	(
		BYTE cbDeltaSize
	);


	ecManager install_hook
	(
		WORD wHookID
	);

	ecManager uninstall_hook
	(
		WORD wHookID
	);

private:
	HANDLE			hHeap,
					hThread,
					hProcess;
	DWORD			dwTargetPID;
	ecManager		ecStatus;
	BOOLEAN			bIsTargetLocal;
	BYTE			cbHookSize;
	LP_HOOK_CONTEXT lpHookData_t;
	LDE				lde_;
};

