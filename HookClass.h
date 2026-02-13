#pragma once
#include <vector>
#include <iostream>
#include <deque>
#include <Windows.h>
#include <winternl.h>
#include "Scanner.h"
#include "LDE.h"


#ifndef hUINT
#define LOCAL_PROCESS_HANDLE reinterpret_cast<HANDLE>(-1)
#define LOCAL_THREAD_HANDLE  reinterpret_cast<HANDLE>(-2)

#define MAX_ITERATIONS 0x8000
#define PAGE_SIZE	   0x10000
#ifdef _M_IX86
typedef unsigned long	   hUINT
#define hkUINT
#define TRAMPOLINE_SIZE 0x07
#elifdef _M_X64
typedef unsigned long long hUINT;
#define hUINT
#define TRAMPOLINE_SIZE 0x0D
#endif
#endif

typedef struct HOOK_CONTEXT {
	LPVOID  lpDetourFunc,
		   *lpOrgFuncAddr,
		    lpTargetFunc;
	BOOLEAN bActive;
	BYTE	cbHookLength,
			org_bytes_arr[TRAMPOLINE_SIZE  + MAX_INSTRUCTION_SIZE],
			patched_bytes_arr[TRAMPOLINE_SIZE + MAX_INSTRUCTION_SIZE];
} *LP_HOOK_CONTEXT;

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation) (
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

typedef NTSTATUS (WINAPI *fnNtQueryInformationProcess) (
	_In_	  HANDLE           hProcessHandle,
	_In_	  PROCESSINFOCLASS process_information_class_t,
	_Out_	  PVOID            pProcessInformation,
	_In_	  ULONG            ulProcessInfoLength,
	_Out_opt_ PULONG           pulReturnLength
);

class HookManager {
public:
	typedef enum ecManager : UCHAR {
		success,
		noInput,
		wrongInput,
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
	Scanner					scanner;
	WORD					wNumberOfHooks;
	std::deque<HOOK_CONTEXT>hkContexts;

	ecManager initializeLocally(_In_ HANDLE hTargetThread);

	ecManager CreateLocalHook(_In_ HOOK_CONTEXT& candidate_hook_ctx, _Out_ LPWORD lpHookID);

	ecManager attachToThread(HANDLE hThread);

	static void generate_nop(BYTE cbDeltaSize, _Inout_ BYTE lpNopNeededAddress[]);

	ecManager install_hook(WORD wHookID);

	ecManager uninstall_hook(WORD wHookID);

private:
	HANDLE	  hThread	  = LOCAL_THREAD_HANDLE,
			  hProcess	  = INVALID_HANDLE_VALUE;
	//DWORD	  dwTargetPID = GetCurrentProcessId();
	ecManager ecStatus	  = success;
	LDE		  lde		  = LDE();
	LPVOID generate_gateway_buffer(HOOK_CONTEXT& candidate_hook_ctx);
};

