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

HookManager::ecManager HookManager::CreateLocalHook(_In_ HOOK_CONTEXT& candidate_hook_ctx, _Out_ LPWORD lpHookId) {
	if (!lpHookId || !candidate_hook_ctx.lpOrgFuncAddr || !candidate_hook_ctx.lpDetourFunc || !candidate_hook_ctx.lpTargetFunc) {
		return noInput;
	}
	LDE_HOOKING_STATE lde_state		= { };
	candidate_hook_ctx.cbHookLength = lde.get_first_valid_instructions_size_hook(&candidate_hook_ctx.lpTargetFunc, lde_state);
	if (!candidate_hook_ctx.cbHookLength) {
		return failedToCalculateHookSize;
	}
	LPBYTE lpHookGateway = static_cast<LPBYTE>(generate_hook_gateway(candidate_hook_ctx)),
		   lpGateway	 = static_cast<LPBYTE>(generate_function_gateway(candidate_hook_ctx, lde_state));
	if (!lpGateway || !lpHookGateway) {
		return failedToAllocateMemory;
	}
	BYTE ucHook_arr[RELATIVE_JUMP_SIZE] = { 0xE9 },
		 cbDelta						= candidate_hook_ctx.cbHookLength - RELATIVE_JUMP_SIZE;
	* reinterpret_cast<int *>(&ucHook_arr[SIZE_OF_BYTE]) = static_cast<int>(reinterpret_cast<LONGLONG>(lpHookGateway) - reinterpret_cast<LONGLONG>(candidate_hook_ctx.lpTargetFunc) - candidate_hook_ctx.cbHookLength);
	if (cbDelta) {
		generate_nop(cbDelta, candidate_hook_ctx.patched_bytes_arr);
		if (!candidate_hook_ctx.patched_bytes_arr[0]) {
			ecStatus = wrong_input;
			return ecStatus;
		}
	}
	memcpy(&candidate_hook_ctx.patched_bytes_arr[cbDelta], &ucHook_arr, RELATIVE_JUMP_SIZE);
	*candidate_hook_ctx.lpOrgFuncAddr = lpGateway;
	*lpHookId = wNumberOfHooks;
	hkContexts.push_back(candidate_hook_ctx);
	wNumberOfHooks++;
	return success;
}

LPVOID HookManager::generate_hook_gateway(HOOK_CONTEXT& candidate_hook_ctx) {
	candidate_hook_ctx.lpHookGateway = MemoryManager.get_adjacent_virtual_buffer(candidate_hook_ctx.lpTargetFunc, TRAMPOLINE_SIZE);
	if (!candidate_hook_ctx.lpHookGateway) {
		ecStatus = failedToAllocateMemory;
		return nullptr;
	}
	BYTE ucHookGateway_arr[TRAMPOLINE_SIZE] = { 0x49, 0xBA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0x41, 0xFF, 0xE2 };
	*reinterpret_cast<LPVOID*>(&ucHookGateway_arr[2]) = candidate_hook_ctx.lpDetourFunc;
	memcpy(candidate_hook_ctx.lpHookGateway, &ucHookGateway_arr, TRAMPOLINE_SIZE);
	return candidate_hook_ctx.lpHookGateway;
}

HookManager::ecManager HookManager::install_hook(_In_ WORD wHookID) {
	switch (is_hook_active_by_hkID(wHookID)) {
		default:
		case INVALID_HOOK_ID: { return wrong_input; }
		case TRUE:			  { return hook_already_active; }
		case FALSE:			  { break; }
	}

	DWORD dwOldProtections  = PAGE_EXECUTE_READ,
		  dwOldProtections2 = NULL;
	if (!VirtualProtect(hkContexts[wHookID].lpHookGateway, TRAMPOLINE_SIZE, dwOldProtections, &dwOldProtections2)) {
		return failedToAllocateMemory;
	}
	if (!VirtualProtect(hkContexts[wHookID].lpFunctionGateway, TRAMPOLINE_SIZE + hkContexts[wHookID].cbHookLength, dwOldProtections, &dwOldProtections2)) {
		return failedToAllocateMemory;
	}
	if (!VirtualProtect(hkContexts[wHookID].lpTargetFunc, hkContexts[wHookID].cbHookLength, PAGE_READWRITE, &dwOldProtections2)) {
		return failedToAllocateMemory;
	}
	perform_data_swap(wHookID);
	if (!VirtualProtect(hkContexts[wHookID].lpTargetFunc, hkContexts[wHookID].cbHookLength, dwOldProtections2, &dwOldProtections)) {
		return failedToAllocateMemory;
	}
	hkContexts[wHookID].status_context |= TRUE;
	return success;
}

void HookManager::generate_nop(_In_ BYTE cbDeltaSize, _Inout_ BYTE lpNopNeededAddress[]) {
	switch (cbDeltaSize) {
		case 1:
			*lpNopNeededAddress  = 0x90;
			break;
		case 2:
			*reinterpret_cast<LPWORD>(lpNopNeededAddress)  = 0x9066;
			break;
		case 3:
			*reinterpret_cast<LPDWORD>(lpNopNeededAddress) = 0x1F0F;
			break;
		case 4:
			*reinterpret_cast<LPDWORD>(lpNopNeededAddress) = 0x401F0F;
			break;
		case 5:
			*reinterpret_cast<LPDWORD>(lpNopNeededAddress) = 0x441F0F;
			break;
		case 6:
			*reinterpret_cast<LPDWORD>(lpNopNeededAddress) = 0x66441F0F;
			break;
		default:
			return;
	}
}

HookManager::ecManager  HookManager::uninstall_hook(_In_ WORD wHookID) {
	DWORD dwOldProtections  = NULL,
	      dwOldProtections2 = PAGE_READWRITE;
	switch (is_hook_active_by_hkID(wHookID)) {
		default:
		case TRUE: {
			break;
		}
		case FALSE: {
			return hook_already_inactive;
		}
		case INVALID_HOOK_ID: {
			return wrong_input;
		}
	}
	if (perform_data_swap(wHookID) != success) {
		return failedToAllocateMemory;
	}

	if (!VirtualProtect(hkContexts[wHookID].lpHookGateway, TRAMPOLINE_SIZE, dwOldProtections2, &dwOldProtections)) {
		return failedToAllocateMemory;
	}

	if (!VirtualProtect(hkContexts[wHookID].lpFunctionGateway, TRAMPOLINE_SIZE + hkContexts[wHookID].cbHookLength, dwOldProtections2, &dwOldProtections)) {
		return failedToAllocateMemory;
	}

	hkContexts[wHookID].status_context = FALSE;
	return success;
}

LPVOID HookManager::generate_function_gateway(HOOK_CONTEXT& candidate_hook_ctx, LDE_HOOKING_STATE& state) {
	candidate_hook_ctx.lpFunctionGateway = MemoryManager.get_adjacent_virtual_buffer(candidate_hook_ctx.lpTargetFunc, candidate_hook_ctx.cbHookLength + TRAMPOLINE_SIZE);
	if (!candidate_hook_ctx.lpFunctionGateway) {
		ecStatus = failedToAllocateMemory;
		return nullptr;
	}
	memcpy(&candidate_hook_ctx.org_bytes_arr, candidate_hook_ctx.lpTargetFunc, candidate_hook_ctx.cbHookLength);
	memcpy(candidate_hook_ctx.lpFunctionGateway, &candidate_hook_ctx.org_bytes_arr, candidate_hook_ctx.cbHookLength);
	LDE::find_n_fix_relocation(static_cast<LPBYTE>(candidate_hook_ctx.lpFunctionGateway), candidate_hook_ctx.lpTargetFunc, state);

	BYTE ucTrampoline_arr[TRAMPOLINE_SIZE] = { 0x49, 0xBA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0x41, 0xFF, 0xE2 };

	*reinterpret_cast<LPVOID*>(&ucTrampoline_arr[2]) = static_cast<LPBYTE>(candidate_hook_ctx.lpTargetFunc) + candidate_hook_ctx.cbHookLength;

	memcpy(&static_cast<LPBYTE>(candidate_hook_ctx.lpFunctionGateway)[candidate_hook_ctx.cbHookLength], &ucTrampoline_arr, TRAMPOLINE_SIZE);

	return candidate_hook_ctx.lpFunctionGateway;
}

HookManager::exchange_size HookManager::generate_exchange_size_by_index(WORD wHookId) const {
	if (hkContexts[wHookId].cbHookLength < 0x08) {
		return eight_bytes;
	}
	if (hkContexts[wHookId].cbHookLength < 0x10) {
		return sixteen_bytes;
	}
	if (hkContexts[wHookId].cbHookLength < 0x18) {
		return extended;
	}
	return unknown;
	
}

BOOLEAN HookManager::is_hook_active_by_hkID(WORD wHookID) const {
	if (wHookID >= wNumberOfHooks) {
		return INVALID_HOOK_ID;
	}
	return static_cast<BOOLEAN>(hkContexts[wHookID].status_context & 0x01);
}

BYTE HookManager::set_hook_active_by_hkID(WORD wHookID) {
	if (wHookID >= wNumberOfHooks) {
		return INVALID_HOOK_ID;
	}
	switch (is_hook_active_by_hkID(wHookID)) {
		default:
		case FALSE: {
			hkContexts[wHookID].status_context &= 0x01;
			return NULL;
		}
		case TRUE: {
			return hook_already_active;
		}
	}
}

HookManager::ecManager HookManager::map_hook_context_by_index(WORD wHookID) {
	BYTE cbDelta;
	switch (generate_exchange_size_by_index(wHookID)) {
		default:
		case unknown: {
			return wrong_input;
		}
		case eight_bytes: {
			hkContexts[wHookID].status_context |= eight_bytes << 6;
			cbDelta = SIZE_OF_QWORD - hkContexts[wHookID].cbHookLength;
			break;
		}
		case sixteen_bytes: {
			cbDelta = SIZE_OF_OWORD - hkContexts[wHookID].cbHookLength;
			hkContexts[wHookID].status_context |= sixteen_bytes << 6;
			break;
		}
		case extended: {
			cbDelta = MAX_INTERLOCKING_HOOK_SIZE - hkContexts[wHookID].cbHookLength;
			hkContexts[wHookID].status_context |= extended << 6;
			break;
		}
	}
	if (cbDelta) {
		memcpy(&hkContexts[wHookID].org_bytes_arr[hkContexts[wHookID].cbHookLength], static_cast<LPBYTE>(hkContexts[wHookID].lpTargetFunc) + hkContexts[wHookID].cbHookLength, cbDelta);
		memcpy(&hkContexts[wHookID].patched_bytes_arr[hkContexts[wHookID].cbHookLength], static_cast<LPBYTE>(hkContexts[wHookID].lpTargetFunc) + hkContexts[wHookID].cbHookLength, cbDelta);
	}
	return success;
}

HookManager::ecManager HookManager::perform_data_swap(WORD wHookID) {
	exchange_size esResult = static_cast<exchange_size>((hkContexts[wHookID].status_context & 0xC0) >> 6);
	if (esResult == unknown) {
		if (map_hook_context_by_index(wHookID) != success) {
			return failedToCalculateHookSize;
		}
		esResult = static_cast<exchange_size>((hkContexts[wHookID].status_context & 0xC0) >> 6);
	}
	PLONGLONG volatile lpTarget = static_cast<PLONGLONG volatile>(hkContexts[wHookID].lpTargetFunc);
	PLONGLONG		   lpSource,
					   lpReference;
	if (hkContexts[wHookID].status_context & 0x01) {
		lpSource	= reinterpret_cast<PLONGLONG>(&hkContexts[wHookID].org_bytes_arr);
		lpReference = reinterpret_cast<PLONGLONG>(&hkContexts[wHookID].patched_bytes_arr);
	} else {
		lpSource	= reinterpret_cast<PLONGLONG>(&hkContexts[wHookID].patched_bytes_arr);
		lpReference = reinterpret_cast<PLONGLONG>(&hkContexts[wHookID].org_bytes_arr);
	}
	DWORD dwOldProtections  = PAGE_READWRITE,
		  dwOldProtections2 = NULL;
	if (!VirtualProtect(hkContexts[wHookID].lpTargetFunc, hkContexts[wHookID].cbHookLength, dwOldProtections, &dwOldProtections2)) {
		return failedToAllocateMemory;
	}
	switch (esResult) {
		case eight_bytes: {
			if (!_InterlockedCompareExchange64(lpTarget, *lpSource, *lpReference)) {
				return failedToAllocateMemory;
			}
			break;
		}
		case sixteen_bytes: {
			if (!_InterlockedCompareExchange128(lpTarget, *lpSource, *(lpSource + 1), lpReference)) {
				return failedToAllocateMemory;
			}
			break;
		}
		case extended: {
			if (!_InterlockedCompareExchange128(static_cast<volatile PLONG64>(hkContexts[wHookID].lpTargetFunc), *lpSource, *(lpSource + 1), lpReference)) {
				return failedToAllocateMemory;
			}
			if (!_InterlockedCompareExchange64(static_cast<volatile PLONGLONG>(hkContexts[wHookID].lpTargetFunc), *(lpSource + 2), *(lpReference + 2))) {
				return failedToAllocateMemory;
			}
			break;
		}
		default:
		case unknown: {
			return wrong_input;
		}
	}
	if (!VirtualProtect(lpTarget, hkContexts[wHookID].cbHookLength, dwOldProtections2, &dwOldProtections)) {
		return failedToAllocateMemory;
	}
	return success;
}