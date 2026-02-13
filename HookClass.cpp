#include "HookClass.h"
HookManager::ecManager HookManager::initializeLocally(_In_ HANDLE hTargetThread) { 
	if (!hTargetThread) {
		return noInput;
	}
	if (hProcess != INVALID_HANDLE_VALUE) {
		return targetIsNotLocal;
	}
	if (!scanner.isThreadInProcess(hTargetThread)) {
		return threadIsNotInProcess;
	}
	hThread = hTargetThread;
	return success;
}

HookManager::ecManager HookManager::attachToThread(HANDLE hThread) { //Place Holder
	return notBuiltYet;
}

HookManager::ecManager HookManager::CreateLocalHook(_In_ HOOK_CONTEXT& candidate_hook_ctx, _Out_ LPWORD lpHookID) {
	if (!lpHookID || !candidate_hook_ctx.lpOrgFuncAddr || !candidate_hook_ctx.lpDetourFunc || !candidate_hook_ctx.lpTargetFunc) {
		return noInput;
	}
	LDE_HOOKING_STATE lde_state	   = { };
	candidate_hook_ctx.cbHookLength  = lde.get_first_valid_instructions_size_hook(&candidate_hook_ctx.lpTargetFunc, lde_state);
	if (!candidate_hook_ctx.cbHookLength) {
		return failedToCalculateHookSize;
	}
	LPBYTE lpGateway = static_cast<LPBYTE>(generate_gateway_buffer(candidate_hook_ctx));
	if (!lpGateway) {
		return failedToAllocateMemory;
	}
	LDE::find_n_fix_relocation(lpGateway, candidate_hook_ctx.lpTargetFunc, lde_state);
	*candidate_hook_ctx.lpOrgFuncAddr				  = lpGateway;
 	BYTE ucHook_arr[TRAMPOLINE_SIZE]				  = { 0x49, 0xBA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0x41, 0xFF, 0xE2 },
		 ucTrampoline_arr[TRAMPOLINE_SIZE]			  = { 0x49, 0xBA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0x41, 0xFF, 0xE2 },
		 cbDelta									  = candidate_hook_ctx.cbHookLength - TRAMPOLINE_SIZE,
		*lpReference								  = static_cast<LPBYTE>(candidate_hook_ctx.lpTargetFunc) + candidate_hook_ctx.cbHookLength;
	* reinterpret_cast<LPVOID*>(&ucHook_arr[2])		  = candidate_hook_ctx.lpDetourFunc;
	* reinterpret_cast<LPVOID*>(&ucTrampoline_arr[2]) = lpReference;
	memcpy(&lpGateway[candidate_hook_ctx.cbHookLength], &ucTrampoline_arr, candidate_hook_ctx.cbHookLength);
	if (cbDelta) {
		LPBYTE lpNop = generate_nop(cbDelta);
		if (!lpNop) {
			ecStatus = failedToAllocateMemory;
			return ecStatus;
		}
		memcpy(&candidate_hook_ctx.patched_bytes_arr, lpNop, cbDelta);
		HeapFree(GetProcessHeap(), NULL, lpNop);
	}
	memcpy(&candidate_hook_ctx.patched_bytes_arr[cbDelta], &ucHook_arr, TRAMPOLINE_SIZE);
	DWORD  dwOldProtections	= NULL;
	VirtualProtect(*candidate_hook_ctx.lpOrgFuncAddr, candidate_hook_ctx.cbHookLength + TRAMPOLINE_SIZE, PAGE_EXECUTE_READ, &dwOldProtections);
	hkContexts.push_back(candidate_hook_ctx);
	*lpHookID = wNumberOfHooks;
	wNumberOfHooks++;
	return success;
}

HookManager::ecManager HookManager::install_hook(_In_ WORD wHookID) {
	DWORD dwOldProtections  = NULL,
		  dwOldProtections2 = PAGE_READWRITE;
	if (wHookID >= wNumberOfHooks) {
		return wrong_input;
	}
	if (hkContexts[wHookID].bActive) {
		return hook_already_active;
	}
	if (!VirtualProtect(hkContexts[wHookID].lpTargetFunc, hkContexts[wHookID].cbHookLength, dwOldProtections2, &dwOldProtections)) {
		return failedToAllocateMemory;
	}
	memcpy(hkContexts[wHookID].lpTargetFunc, &hkContexts[wHookID].patched_bytes_arr, hkContexts[wHookID].cbHookLength);
	if (!VirtualProtect(hkContexts[wHookID].lpTargetFunc, hkContexts[wHookID].cbHookLength, dwOldProtections, &dwOldProtections2)) {
		return failedToAllocateMemory;
	}
	hkContexts[wHookID].bActive = TRUE;
	return success;
}

LPBYTE HookManager::generate_nop(_In_ BYTE cbDeltaSize) {
	if (!cbDeltaSize) {
		return nullptr;
	}
	LPVOID lpNOP = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbDeltaSize);
	if (!lpNOP) {
		return nullptr;
	}
	switch (cbDeltaSize) {
		case 1:
			*static_cast<LPBYTE>(lpNOP)  = 0x90;
			break;
		case 2:
			*static_cast<LPWORD>(lpNOP)  = 0x9066;
			break;
		case 3:
			*static_cast<LPDWORD>(lpNOP) = 0x1F0F;
			break;
		case 4:
			*static_cast<LPDWORD>(lpNOP) = 0x401F0F;
			break;
		case 5:
			*static_cast<LPDWORD>(lpNOP) = 0x441F0F;
			break;
		case 6:
			*static_cast<LPDWORD>(lpNOP) = 0x66441F0F;
			break;
		default:
			return nullptr;
	}
	return static_cast<LPBYTE>(lpNOP);
}

HookManager::ecManager  HookManager::uninstall_hook(_In_ WORD wHookID) {
	DWORD dwOldProtections  = NULL,
	      dwOldProtections2 = PAGE_READWRITE;
	if (wHookID >= wNumberOfHooks) {
		return wrong_input;
	}
	if (!hkContexts[wHookID].bActive) {
		return hook_already_inactive;
	}
	if (!VirtualProtect(hkContexts[wHookID].lpTargetFunc, hkContexts[wHookID].cbHookLength, dwOldProtections2, &dwOldProtections)) {
		return failedToAllocateMemory;
	}
	memcpy(hkContexts[wHookID].lpTargetFunc, &hkContexts[wHookID].org_bytes_arr, hkContexts[wHookID].cbHookLength);
	if (!VirtualProtect(hkContexts[wHookID].lpTargetFunc, hkContexts[wHookID].cbHookLength, dwOldProtections, &dwOldProtections2)) {
		return failedToAllocateMemory;
	}
	hkContexts[wHookID].bActive = FALSE;
	return success;
}

LPVOID HookManager::generate_gateway_buffer(HOOK_CONTEXT& candidate_hook_ctx) {
	
	LPVOID lpFoundAddress = scanner.get_adjacent_memory_i32bit(scanner.get_local_module_handle_by_function(candidate_hook_ctx.lpTargetFunc));
	if (!lpFoundAddress) {
		ecStatus = failedToAllocateMemory;
		return nullptr;
	}
	LPBYTE lpGateway = static_cast<LPBYTE>(VirtualAlloc(lpFoundAddress, candidate_hook_ctx.cbHookLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!lpGateway) {
		ecStatus = failedToAllocateMemory;
		return nullptr;
	}
	memcpy(&candidate_hook_ctx.org_bytes_arr, candidate_hook_ctx.lpTargetFunc, candidate_hook_ctx.cbHookLength);
	memcpy(lpGateway, &candidate_hook_ctx.org_bytes_arr, candidate_hook_ctx.cbHookLength);
	return lpGateway;
}
