#include "HookClass.h"



HookManager::ecManager HookManager::initializeLocally
(
	_In_ HANDLE hTargetThread
)
{
	if (!hTargetThread) {
		return noInput;
	}

	if (hProcess != INVALID_HANDLE_VALUE) {
		return targetIsNotLocal;
	}

	if (!pScanner->isThreadInProcess(hTargetThread)) {
		return threadIsNotInProcess;
	}

	hThread = hTargetThread;

	return success;
}

HookManager::ecManager HookManager::attachToThread(HANDLE hThread) // Place Holder
{
	if (!pScanner) {
		return success;
	}
	return failedToGetProcessHeap;
}

HookManager::ecManager HookManager::CreateLocalHook
(
	_In_  LP_HOOK_CONTEXT pCandidateHookData_t, 
	_Out_ LPWORD lpHookID
)
{
	if (!pCandidateHookData_t || !lpHookID) {
		return noInput;
	}

	if (   !pCandidateHookData_t->lpOrgFuncAddr 
		|| !pCandidateHookData_t->lpDetourFunc 
		|| !pCandidateHookData_t->lpTargetFunc
		) {
		return noInput;
	}

	LDE_HOOKING_STATE		 lde_state	  = { };
	BYTE					 ucSafeLength = lde_.getGreaterFullInstLen(&pCandidateHookData_t->lpTargetFunc, lde_state);
	if (!ucSafeLength) {
		return failedToCalculateHookSize;
	}
	MEMORY_BASIC_INFORMATION MemBasicInfo_t{};
	LPVOID					 lpTrampoline_target_addr = nullptr;
	LPBYTE					 lpTrampoline	  = nullptr,
							 lpNop			  = nullptr;
	LONGLONG				 llIterations	  = 1; //the last byte of the dll's size is allocated for the dll, let's start looking on the next page
	DWORD					 dwOldProtections = NULL;
	pScanner->getLocalModuleHandleByFunction(pCandidateHookData_t->lpTargetFunc);//used to indirectly map the correct module's data, this will be handled in a separate method later.

	while (llIterations < 0x8000) {
		DWORD64 llModuleBaseOffset = pScanner->pModuleData->ullImageSize + (llIterations * 0x10000);
		VirtualQuery(static_cast<LPBYTE>(pScanner->pModuleData->pModuleLDR->Reserved2[0]) + llModuleBaseOffset , &MemBasicInfo_t, sizeof(MEMORY_BASIC_INFORMATION));
		if (MemBasicInfo_t.State == MEM_FREE) {
			std::cout << std::format("[!] Found It! (Using: {:d} Iterations) Offset: {:#X} \n[i] Page Base Address: {:#X}\n",llIterations - 1, llModuleBaseOffset, reinterpret_cast<ULONGLONG>(MemBasicInfo_t.BaseAddress));
			lpTrampoline_target_addr = MemBasicInfo_t.BaseAddress;
			break;
		}
		llIterations++;
	}

	if(!(lpTrampoline = static_cast<LPBYTE>(VirtualAlloc(lpTrampoline_target_addr, ucSafeLength + TRAMPOLINE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))) {
		ecStatus = failedToAllocateMemory;
		return failedToAllocateMemory;
	}

	memcpy(&pCandidateHookData_t->org_bytes_arr, pCandidateHookData_t->lpTargetFunc, ucSafeLength);
	memcpy(lpTrampoline, &pCandidateHookData_t->org_bytes_arr, ucSafeLength);

	lde_.find_n_fix_relocation(lpTrampoline, pCandidateHookData_t->lpTargetFunc, lde_state);

	*pCandidateHookData_t->lpOrgFuncAddr = lpTrampoline;

	BYTE   ucHook_arr	   [TRAMPOLINE_SIZE]{ 0x49, 0xBA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0x41, 0xFF, 0xE2 },
		   ucTrampoline_arr[TRAMPOLINE_SIZE]{ 0x49, 0xBA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0x41, 0xFF, 0xE2 },
		   cbDelta	   = ucSafeLength - TRAMPOLINE_SIZE,
		  *lpReference = static_cast<LPBYTE>(pCandidateHookData_t->lpTargetFunc) + ucSafeLength;

	memcpy(&ucHook_arr[2], &pCandidateHookData_t->lpDetourFunc, sizeof(LPVOID));
	memcpy(&ucTrampoline_arr[2], &lpReference , sizeof(LPVOID));
	memcpy(&lpTrampoline[ucSafeLength], &ucTrampoline_arr, ucSafeLength);

	if (!(lpNop = generate_nop(cbDelta))) {
		ecStatus = failedToAllocateMemory;
		return failedToAllocateMemory;
	}

	memcpy(&pCandidateHookData_t->patched_bytes_arr, lpNop, cbDelta);
	memcpy(&pCandidateHookData_t->patched_bytes_arr[cbDelta], &ucHook_arr, TRAMPOLINE_SIZE);
	*pCandidateHookData_t->lpOrgFuncAddr = *reinterpret_cast<LPVOID *>(&lpTrampoline);
	pCandidateHookData_t->cbHookLength	 = ucSafeLength;
	VirtualProtect(*pCandidateHookData_t->lpOrgFuncAddr, ucSafeLength + TRAMPOLINE_SIZE, PAGE_EXECUTE_READ, &dwOldProtections);
	hkContexts.push_back(*pCandidateHookData_t);
	*lpHookID = wNumberOfHooks;
	wNumberOfHooks++;
	return success;
}


HookManager::ecManager HookManager::install_hook
(
	_In_ WORD wHookID
)
{

	DWORD dwOldProtections = NULL,
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

LPBYTE HookManager::generate_nop
(
	_In_ BYTE cbDeltaSize
)
{
	if (!cbDeltaSize)
		return nullptr;

	LPBYTE lpNOP = static_cast<LPBYTE>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbDeltaSize));
	if (!lpNOP) {
		return nullptr;
	}

	switch (cbDeltaSize) {
		case 1:
			lpNOP[0] = 0x90;
			break;
		case 2:
			lpNOP[0] = 0x66;
			lpNOP[1] = 0x90;
			break;
		case 3:
			lpNOP[0] = 0x0F;
			lpNOP[1] = 0x1F;
			break;
		case 4:
			lpNOP[0] = 0x0F;
			lpNOP[1] = 0x1F;
			lpNOP[2] = 0x40;
			break;
		case 5:
			lpNOP[0] = 0x0F;
			lpNOP[1] = 0x1F;
			lpNOP[2] = 0x44;
			break;
		case 6:
			lpNOP[0] = 0x66;
			lpNOP[1] = 0x0F;
			lpNOP[2] = 0x1F;
			lpNOP[3] = 0x44;
			break;
		default:
			break;
	}
	return lpNOP;
}

HookManager::ecManager  HookManager::uninstall_hook
(
	_In_ WORD wHookID
)
{
	DWORD dwOldProtections = NULL,
	      dwOldProtections2 = PAGE_READWRITE;
	if (wHookID >= wNumberOfHooks)
	{
		return wrong_input;
	}
	if (!hkContexts[wHookID].bActive)
		return hook_already_inactive;

	if (!VirtualProtect(hkContexts[wHookID].lpTargetFunc, hkContexts[wHookID].cbHookLength, dwOldProtections2, &dwOldProtections))
		return failedToAllocateMemory;

	memcpy(hkContexts[wHookID].lpTargetFunc, &hkContexts[wHookID].org_bytes_arr, hkContexts[wHookID].cbHookLength);

	if (!VirtualProtect(hkContexts[wHookID].lpTargetFunc, hkContexts[wHookID].cbHookLength, dwOldProtections, &dwOldProtections2))
		return failedToAllocateMemory;

	hkContexts[wHookID].bActive = FALSE;

	return success;
	
}