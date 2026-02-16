#pragma once

#include <Windows.h>
#include <vector>
#include <iostream>
#include <deque>
#include "Scanner.h"
#include "LDE.h"
#include "hooks_memory_manager.h"


#ifndef hUINT
#define LOCAL_PROCESS_HANDLE reinterpret_cast<HANDLE>(-1)
#define LOCAL_THREAD_HANDLE  reinterpret_cast<HANDLE>(-2)

#define MAX_ITERATIONS 0x8000
#define PAGE_SIZE	   0x10000
#ifdef _M_IX86
typedef unsigned long	   hUINT
#define hkUINT
#define TRAMPOLINE_SIZE 0x100
#elifdef _M_X64
typedef unsigned long long hUINT;
#define hUINT
#define TRAMPOLINE_SIZE 0x0D
#endif
#endif
constexpr BYTE   RELATIVE_JUMP_SIZE			= 0x05,
				 MAX_INTERLOCKING_HOOK_SIZE = 0x18,
			     INVALID_HOOK_ID			= 0xFF;
typedef unsigned char HOOK_STATUS_CONTEXT;
typedef struct HOOK_CONTEXT {
	LPVOID  lpDetourFunc,
		   *lpOrgFuncAddr,
		    lpTargetFunc,
			lpHookGateway,
			lpFunctionGateway;
	HOOK_STATUS_CONTEXT status_context;
	BYTE	cbHookLength,
			org_bytes_arr[MAX_INTERLOCKING_HOOK_SIZE],
			patched_bytes_arr[MAX_INTERLOCKING_HOOK_SIZE];
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
		function_not_found_in_modules,
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

	ecManager CreateLocalHook(_In_ HOOK_CONTEXT& candidate_hook_ctx, _Out_ LPWORD lpHookId);

	ecManager attachToThread(HANDLE hThread);

	static void generate_nop(BYTE cbDeltaSize, _Inout_ BYTE lpNopNeededAddress[]);

	ecManager install_hook(WORD wHookID);

	ecManager uninstall_hook(WORD wHookID);

private:
	enum exchange_size : BYTE {
		unknown		  = 0x00, 
		eight_bytes   = 0x01,
		sixteen_bytes = 0x02,
		extended	  = 0x03
	};
	HANDLE	  hThread	  = LOCAL_THREAD_HANDLE,
			  hProcess	  = INVALID_HANDLE_VALUE;
	//DWORD	  dwTargetPID = GetCurrentProcessId();
	ecManager ecStatus	  = success;
	LDE		  lde		  = LDE();

	HookingMemoryManager MemoryManager = HookingMemoryManager(scanner);

	LPVOID generate_hook_gateway(HOOK_CONTEXT& candidate_hook_ctx);

	LPVOID generate_function_gateway(HOOK_CONTEXT& candidate_hook_ctx, LDE_HOOKING_STATE& state);

	inline BYTE is_hook_active_by_hkID(WORD wHookID) const;

	exchange_size generate_exchange_size_by_index(WORD wHookId) const;

	BYTE inline set_hook_active_by_hkID(WORD wHookID);

	ecManager map_hook_context_by_index(WORD wHookID);

	ecManager perform_data_swap(WORD wHookID);
};

