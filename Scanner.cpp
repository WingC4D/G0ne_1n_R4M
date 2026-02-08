#include "Scanner.h"
PPEB Scanner::getLocalPeb() {
#ifdef _M_IX86_
	return reinterpret_cast<PPEB>(__readfsbyte(0x30));
#elif _WIN64
	return reinterpret_cast<PPEB>(__readgsqword(0x60));
#endif
}

hkUINT GenerateHashA(_In_ LPCSTR lpStringToHash) {
	CHAR  cChar;
	hkUINT uiHash = NULL,
		uiSeed = ct::g_Seed;
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

hkUINT GenerateHashW(LPWSTR lpStringToHash) {
	WORD  wChar   = NULL;
	hkUINT uiHash = NULL;
	while ((wChar = *lpStringToHash++) != NULL) {
		uiHash += wChar;
		uiHash += uiHash << (ct::g_Seed & 0x3F);
		uiHash ^= uiHash >> 6;
	}

	uiHash += uiHash << 3;
	uiHash ^= uiHash >> 11;
	uiHash += uiHash << 15;

	return uiHash;
}

Scanner::Scanner(_In_ HANDLE hTargetProcess) {
	dwTargetTID = NULL;
	dwTargetPID = NULL;
	hProcess = nullptr;
	hThread = nullptr;
	pModuleData = nullptr;
	wTargetOrdinal = NULL;
	dwFuncSize = NULL;
	hHeap = GetProcessHeap();
	if (!hHeap || hHeap == INVALID_HANDLE_VALUE) {
		ecStatus = failedToGetHeapHandle;
		return;
	}
	if (hTargetProcess == INVALID_HANDLE_VALUE) {
		bIsLocal = TRUE;
	} else if (!hTargetProcess) {
		hTargetProcess = INVALID_HANDLE_VALUE;
		bIsLocal = TRUE;
	} else {
		std::cout << "[i] You still haven't designed a remote process hooking system!\n";
		bIsLocal = FALSE;
		ecStatus = notBuiltYet;
		return;
	}
	if (!(dwTargetPID = GetProcessId(hTargetProcess))) {
		ecStatus = badProcessHandle;
		return;
	}
	hProcess = hTargetProcess;
	if (bIsLocal) {
		if (!(pTargetPEB = getLocalPeb())) {
			ecStatus = failedToFetchLocalPEB;
			return;
		}
	} else {
		ecStatus = notBuiltYet;
		return;
	}
	ecStatus = success;
}

BOOLEAN Scanner::isThreadInProcess(HANDLE hCandidateThread) {
	if (!hCandidateThread || hCandidateThread == INVALID_HANDLE_VALUE) {
		ecStatus = noInput;
		return FALSE;
	}
	if (!hProcess) {
		ecStatus = noProcessAttached;
		return FALSE;
	}
	if (!(dwTargetTID = GetThreadId(hCandidateThread))) {
		ecStatus = invalidHandle;
		return FALSE;
	}

	fnNtQuerySystemInformation fnNtQueryInfoProc = reinterpret_cast<fnNtQuerySystemInformation>(getProcAddressH(getModuleHandleH(ct::nt_dll), ct::nt_query_sys_info));

	if (!fnNtQueryInfoProc) {
		ecStatus = failedToFindNtQuerySysInfo;
		return FALSE;
	}
	PSYSTEM_THREAD_INFORMATION  pSysThreadInfo_t   = nullptr;
	PSYSTEM_PROCESS_INFORMATION pSystemProcInfo_t  = nullptr;
	ULONG					    ulSysProcInfoSize  = NULL,
								ulFunctionRetSize  = NULL;
	NTSTATUS				    ntStatus		   = ERROR_SUCCESS;

	fnNtQueryInfoProc(SystemProcessInformation, nullptr, NULL, &ulSysProcInfoSize);

	if (!ulSysProcInfoSize) {
		ecStatus = failedToFindSysProcInfoSize;
		return FALSE;
	}
	std::vector<BYTE>pSystemProcVector(ulSysProcInfoSize);
	if (!(pSystemProcInfo_t = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pSystemProcVector.data()))) {
		ecStatus = failedToAllocateMemory;
		return FALSE;
	}
	if ((ntStatus = fnNtQueryInfoProc(SystemProcessInformation, pSystemProcInfo_t, ulSysProcInfoSize, &ulFunctionRetSize)) > NULL) {
		ecStatus = failedToFindSysProcInfo;
		
		return FALSE;
	}
	if (!ulSysProcInfoSize) {
		ecStatus = failedToFindSysProcInfoSize;
		return FALSE;
	}
	while (pSystemProcInfo_t->NextEntryOffset) {
		if (pSystemProcInfo_t->UniqueProcessId == reinterpret_cast<HANDLE>(dwTargetPID)) {
			break;
		}
		pSystemProcInfo_t = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<PBYTE>(pSystemProcInfo_t) + pSystemProcInfo_t->NextEntryOffset);
	}
	if (!pSystemProcInfo_t->NextEntryOffset) {
		ecStatus = processEnumerationFailed;
		return FALSE;
	}
	pSysThreadInfo_t = reinterpret_cast<PSYSTEM_THREAD_INFORMATION>(reinterpret_cast<PBYTE>(pSystemProcInfo_t) + sizeof(SYSTEM_PROCESS_INFORMATION));
	for (unsigned int i = 0; i < pSystemProcInfo_t->NumberOfThreads; i++) {
		if (pSysThreadInfo_t->ClientId.UniqueProcess != pSystemProcInfo_t->UniqueProcessId) {
			ecStatus = threadEnumerationFailed;
			return FALSE;
		}
		if (pSysThreadInfo_t->ClientId.UniqueThread == reinterpret_cast<HANDLE>(dwTargetTID)) {
			pSystemProcInfo = std::vector<BYTE>(sizeof(SYSTEM_PROCESS_INFORMATION) + pSystemProcInfo_t->NumberOfThreads * sizeof(SYSTEM_THREAD_INFORMATION));
			if (!(pSystemProcInfo_t)) {
				ecStatus = failedToAllocateMemory;
				return FALSE;
			}
			memcpy(pSystemProcInfo.data(), pSystemProcInfo_t, sizeof(SYSTEM_PROCESS_INFORMATION) + pSystemProcInfo_t->NumberOfThreads * sizeof(SYSTEM_THREAD_INFORMATION));
			ecStatus = success;
			return TRUE;
		}
		pSysThreadInfo_t = reinterpret_cast<PSYSTEM_THREAD_INFORMATION>(reinterpret_cast<PBYTE>(pSysThreadInfo_t) + sizeof(SYSTEM_THREAD_INFORMATION));
	}
	ecStatus = threadIsNotInProcess;
	return FALSE;
}

BOOLEAN Scanner::isThreadLocal(HANDLE hThread) {
	fnNtQueryInformationProcess pNtQuerySysInfo = nullptr;
	switch (reinterpret_cast<hkUINT>(hThread)) {
		case reinterpret_cast<hkUINT>(LOCAL_THREAD_HANDLE): {
			return TRUE;
		}
		case reinterpret_cast<hkUINT>(nullptr):
		case reinterpret_cast<hkUINT>(INVALID_HANDLE_VALUE): {
				hThread = LOCAL_THREAD_HANDLE;
				return TRUE;
		}
		default: {
			if (!(pNtQuerySysInfo = reinterpret_cast<fnNtQueryInformationProcess>(getProcAddressH(getModuleHandleH(ct::nt_dll), ct::nt_query_info_proc)))) {
				ecStatus = failedToFindNtQuerySysInfo;
				return FALSE;
			}
		}
	}
	return FALSE;
}

Scanner::scannerErrorCode  Scanner::getLastError() const {
	return ecStatus;
}

BOOLEAN Scanner::validateLocalPEB() {
	if (!pTargetPEB) {
		if (!(pTargetPEB = getLocalPeb())) {
			ecStatus = failedToFetchLocalPEB;
			return FALSE;
		}
	}
	return TRUE;
}

HMODULE Scanner::getModuleHandleH(hkUINT uiHashedModuleName) {
	if (!validateLocalPEB()) {
		return nullptr;
	}
	PPEB_LDR_DATA		  pPebLdrData	 = this->pTargetPEB->Ldr;
	PLIST_ENTRY		      pListHeadEntry = pPebLdrData->InMemoryOrderModuleList.Flink,
						  pCurrEntry	 = pListHeadEntry;
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pCurrEntry);

	do {
		if (GenerateHashW(pLdrDataTableEntry->FullDllName.Buffer) == uiHashedModuleName) {
			mapModuleData(pLdrDataTableEntry);
			return static_cast<HMODULE>(pModuleData->pModuleLDR->Reserved2[0]);
		}
		pCurrEntry = pCurrEntry->Flink;
		pLdrDataTableEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pCurrEntry);

	} while (pCurrEntry != pListHeadEntry);

	return nullptr;
}
FARPROC Scanner::getProcAddressH(
	IN       HMODULE hModule,
	_In_	 hkUINT   uiHashedName
) {
	if (!hModule || !uiHashedName) {
		ecStatus = noInput;
		return nullptr;
	}
	if (hModule == INVALID_HANDLE_VALUE) {
		ecStatus = invalidHandle;
		return nullptr;
	}
	if (!bIsLocal) {
		ecStatus = notBuiltYet;
		return nullptr;
	}
	if (!validateLocalPEB()) {
		ecStatus = failedToFetchLocalPEB;
		return nullptr;
	}
	PIMAGE_EXPORT_DIRECTORY pModuleExportDirectory = getImageExportDirectory(reinterpret_cast<LPBYTE>(hModule));
	if (!pModuleExportDirectory) {
		return nullptr;
	}
	for (DWORD i = 0; i < pModuleExportDirectory->NumberOfNames; i++) {
		if (uiHashedName == GenerateHashA(reinterpret_cast<LPSTR>(pModuleData->lpModuleBaseAddr + pModuleData->lpNamesRVA_arr[i]))) {
			ecStatus = success;
			wTargetOrdinal = reinterpret_cast<WORD>(pModuleData->lpModuleBaseAddr + pModuleData->lpOrdsRVA_arr[i]);
			return reinterpret_cast<FARPROC>(pModuleData->lpModuleBaseAddr + pModuleData->lpFunctionsRVA_arr[wTargetOrdinal]);
		}
	}
	ecStatus = failedToFindTargetFuncOrdinal;
	return nullptr;
}


PIMAGE_OPTIONAL_HEADER Scanner::get_image_optional_headers(LPBYTE pImageBase) {
	if (!pImageBase) {
		ecStatus = noInput;
		return nullptr;
	}
	if (pImageBase == INVALID_HANDLE_VALUE) {
		ecStatus = invalidHandle;
		return nullptr;
	}
	PIMAGE_DOS_HEADER pImageDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageBase);
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		ecStatus = invalidDosHeader;
		return nullptr;
	}
	PIMAGE_NT_HEADERS pImageNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<LPBYTE>(pImageDosHeader) + pImageDosHeader->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		ecStatus = invalidPeHeader;
		return nullptr;
	}
	if (pImageNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		ecStatus = invalidOptionalHeader;
		return nullptr;
	}
	return &pImageNtHeader->OptionalHeader;

}

PIMAGE_EXPORT_DIRECTORY Scanner::getImageExportDirectory(LPBYTE pImageBase)
{
	if (!pImageBase) {
		ecStatus = noInput;
		return nullptr;
	}

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeader = get_image_optional_headers(pImageBase);

	if (!pImageOptionalHeader) {
		ecStatus = failedToGetExportDir;
		return nullptr;
	}

	if (pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
		ecStatus = success;
		return reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pImageBase + pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}

	ecStatus = emptyExportDirectory;
	return nullptr;
}

Scanner::scannerErrorCode Scanner::mapModuleData(PLDR_DATA_TABLE_ENTRY lpModuleLDR)
{
	PIMAGE_OPTIONAL_HEADER pImageOptionalHeader = get_image_optional_headers((LPBYTE)lpModuleLDR->Reserved2[0]);

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((LPBYTE)lpModuleLDR->Reserved2[0] + pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if (!pImageExportDirectory) {
		return failedToGetExportDir;
	}
	if (!pModuleData) {
		pModuleData = std::make_unique<MODULE_DATA>();
		if (!pModuleData) {
			return failedToAllocateMemory;
		}
	}
	pModuleData->ullImageSize		 = pImageOptionalHeader->SizeOfImage;
	pModuleData->pModuleLDR			 = lpModuleLDR;
	pModuleData->lpModuleBaseAddr	 = static_cast<LPBYTE>(pModuleData->pModuleLDR->Reserved2[0]);
	pModuleData->lpFunctionsRVA_arr  = reinterpret_cast<LPDWORD>(pModuleData->lpModuleBaseAddr + pImageExportDirectory->AddressOfFunctions);
	pModuleData->lpNamesRVA_arr		 = reinterpret_cast<LPDWORD>(pModuleData->lpModuleBaseAddr + pImageExportDirectory->AddressOfNames);
	pModuleData->lpOrdsRVA_arr		 = reinterpret_cast<LPWORD>(pModuleData->lpModuleBaseAddr + pImageExportDirectory->AddressOfNameOrdinals);
	pModuleData->dwNumberOfNames	 = pImageExportDirectory->NumberOfNames;
	pModuleData->dwNumberOfFunctions = pImageExportDirectory->NumberOfFunctions;

	return success;
}

HMODULE Scanner::getLocalModuleHandleByFunction(LPVOID lpFunctionAddress) {
	if (!validateLocalPEB()) {
		ecStatus = failedToFetchLocalPEB;
		return nullptr;
	}
	PPEB_LDR_DATA		   pPebLdrData	  = pTargetPEB->Ldr;
	PLIST_ENTRY			   pListHeadEntry = pPebLdrData->InMemoryOrderModuleList.Flink,
						   pCurrListEntry = pListHeadEntry;
	PLDR_DATA_TABLE_ENTRY  pCurrLDR_Entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pCurrListEntry);
	
	do {
		if (lpFunctionAddress > pCurrLDR_Entry->Reserved2[0] &&
			reinterpret_cast<hkUINT>(lpFunctionAddress) < reinterpret_cast<hkUINT>(pCurrLDR_Entry->Reserved2[0]) + reinterpret_cast<hkUINT>(pCurrLDR_Entry->DllBase)) {
			//std::wcout << L"[!] Found The Desired Function In: " << pCurrLDR_Entry->FullDllName.Buffer;
			//std::cout << std::format(" Found: {:p}  between {:p} & {:#10x}\n", lpFunctionAddress,  pCurrLDR_Entry->Reserved2[0], reinterpret_cast<hkUINT>(pCurrLDR_Entry->Reserved2[0]) + reinterpret_cast<hkUINT>(pCurrLDR_Entry->DllBase));
			mapModuleData(pCurrLDR_Entry);
			ecStatus = success;
			return static_cast<HMODULE>(pCurrLDR_Entry->Reserved2[0]);

		}
		//std::wcout << "[x] Was Not Found In: " << pCurrLDR_Entry->FullDllName.Buffer;
		//std::cout << std::format(" between {:p} & {:#10x}\n", pCurrLDR_Entry->Reserved2[0], reinterpret_cast<hkUINT>(pCurrLDR_Entry->Reserved2[0]) + reinterpret_cast<hkUINT>(pCurrLDR_Entry->DllBase));
		pCurrListEntry = pCurrListEntry->Flink;
		pCurrLDR_Entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pCurrListEntry);
	} while (pCurrListEntry != pListHeadEntry);
	ecStatus = failedToFindModule;
	return nullptr;
}

WORD Scanner::getFuncOrdinal(LPVOID lpFunctionAddress) {
	if (!lpFunctionAddress) {
		ecStatus = noInput;
		return NULL;
	}
	HMODULE hModule = getLocalModuleHandleByFunction(lpFunctionAddress);
	if (!hModule) {
		ecStatus = failedToFindModule;
		return 0;
	}

	for (DWORD i = 0; i < pModuleData->dwNumberOfFunctions; i++) {
		if (lpFunctionAddress == reinterpret_cast<LPVOID>(pModuleData->lpModuleBaseAddr + pModuleData->lpFunctionsRVA_arr[pModuleData->lpOrdsRVA_arr[i]])) {
			ecStatus = success;
			return pModuleData->lpOrdsRVA_arr[i];
		}
	}
	ecStatus = failedToFindTargetFuncOrdinal;
	return 0;
}
