#include "hooks_memory_manager.h"

HookingMemoryManager::HookingMemoryManager(Scanner& scanner_ref) {
	scanner = &scanner_ref;

	modules_data_deque = std::deque<HOOKS_MODULE_DATA>(NULL);

	map_all_local_modules();
}

void HookingMemoryManager::map_all_local_modules() {
	if (!scanner->validateLocalPEB()) {
		return;
	}
	PLIST_ENTRY pHeadListEntry	 = scanner->pTargetPEB->Ldr->InMemoryOrderModuleList.Flink,
				pCurrentListEntry  = pHeadListEntry;
	do {
		PIMAGE_EXPORT_DIRECTORY			 pCurrentModuleExportDirectory = nullptr;
		DWORD							 dwCurrentModuleSize		   = NULL;
		const PLDR_DATA_TABLE_ENTRY		 pLdrDataTableEntry			   = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pCurrentListEntry);
		if (const PIMAGE_OPTIONAL_HEADER pCurrentModuleOptionalHeader  = scanner->get_image_optional_headers(static_cast<LPBYTE>(pLdrDataTableEntry->Reserved2[0]))) {
			pCurrentModuleExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(static_cast<LPBYTE>(pLdrDataTableEntry->Reserved2[0]) + pCurrentModuleOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			dwCurrentModuleSize			  = pCurrentModuleOptionalHeader->SizeOfImage;
		}
		HOOKS_MODULE_DATA module_data_t = {
			static_cast<LPBYTE>(pLdrDataTableEntry->Reserved2[0]),
			pLdrDataTableEntry,
			pCurrentModuleExportDirectory,
			dwCurrentModuleSize
		};
		modules_data_deque.push_back(module_data_t);
		pCurrentListEntry = pCurrentListEntry->Flink;
	} while (pCurrentListEntry != pHeadListEntry);
}

hkUINT HookingMemoryManager::get_local_module_index_by_function(LPVOID lpFunctionAddress) const {
	hkUINT uiIndex		  = NULL,
		   uiNumOfModules = modules_data_deque.size();
	while (uiIndex < uiNumOfModules) {
		if (lpFunctionAddress > modules_data_deque[uiIndex].lpModuleBaseAddr &&
			lpFunctionAddress < modules_data_deque[uiIndex].lpModuleBaseAddr + modules_data_deque[uiIndex].dwModuleSize) {
			return uiIndex;
		}
		uiIndex++;
	}
	return INVALID_MODULE_INDEX;
}

HMODULE HookingMemoryManager::get_local_module_handle_by_function(LPVOID lpFunctionAddress) const {
	hkUINT uiIndex = get_local_module_index_by_function(lpFunctionAddress);
	if (uiIndex == INVALID_MODULE_INDEX) {
		return nullptr;
	}
	return reinterpret_cast<HMODULE>(modules_data_deque[uiIndex].lpModuleBaseAddr);
}

optimal_hook_location HookingMemoryManager::check_where_to_place_hook_by_function(LPVOID lpTargetFunction) const {
	hkUINT uiIndex			= get_local_module_index_by_function(lpTargetFunction),
		   uiNewDisposition = reinterpret_cast<hkUINT>(modules_data_deque[uiIndex].lpModuleBaseAddr + modules_data_deque[uiIndex].dwModuleSize + modules_data_deque[uiIndex].wPostModuleAllocatedSize - reinterpret_cast<hkUINT>(lpTargetFunction));
	if (uiNewDisposition > TWO_GIGABYTES) {
		if (uiNewDisposition - modules_data_deque[uiIndex].dwModuleSize  - modules_data_deque[uiIndex].wPostModuleAllocatedSize - modules_data_deque[uiIndex].wPreModuleAllocatedSize > 0x80000000) {
			return unknown;
		}
		return before_the_module;
	}
	return after_the_module;
}

optimal_hook_location HookingMemoryManager::check_where_to_place_hook_by_index(LPVOID lpTargetFunction, hkUINT uiIndex) const {
	hkUINT uiNewDisposition = reinterpret_cast<hkUINT>(modules_data_deque[uiIndex].lpModuleBaseAddr + modules_data_deque[uiIndex].dwModuleSize + modules_data_deque[uiIndex].wPostModuleAllocatedSize - reinterpret_cast<hkUINT>(lpTargetFunction));
	if (uiNewDisposition > TWO_GIGABYTES) {
		if (uiNewDisposition - modules_data_deque[uiIndex].dwModuleSize - modules_data_deque[uiIndex].wPostModuleAllocatedSize - modules_data_deque[uiIndex].wPreModuleAllocatedSize > 0x80000000) {
			return unknown;
		}
		return before_the_module;
	}
	return after_the_module;
}

LPVOID HookingMemoryManager::get_adjacent_virtual_buffer(LPVOID lpTargetAddress, WORD uiNeededSize) {
	if (!lpTargetAddress) {
		return nullptr;
	}
	hkUINT				  uiModuleIndex = get_local_module_index_by_function(lpTargetAddress),
						  uiNewPostDisposition = reinterpret_cast<hkUINT>(modules_data_deque[uiModuleIndex].lpModuleBaseAddr + modules_data_deque[uiModuleIndex].dwModuleSize + modules_data_deque[uiModuleIndex].wPostModuleAllocatedSize - reinterpret_cast<hkUINT>(lpTargetAddress));
	optimal_hook_location result = unknown;
	if (uiNewPostDisposition < TWO_GIGABYTES) {
		result = after_the_module;
	} else {
		LONGLONG iNewPreDisposition = static_cast<LONGLONG>(reinterpret_cast<hkUINT>(lpTargetAddress) - reinterpret_cast<hkUINT>(modules_data_deque[uiModuleIndex].lpModuleBaseAddr) - modules_data_deque[uiModuleIndex].wPreModuleAllocatedSize);
		if (iNewPreDisposition > -TWO_GIGABYTES) {
			result = before_the_module;
		}
	}
	switch (result) {
		case unknown: {
			return nullptr;
		}
		case after_the_module: {
			if (!modules_data_deque[uiModuleIndex].lpHooksPostAllocationBase) {
				LPVOID lpFoundAddress = Scanner::get_adjacent_memory_forward_i32bit(reinterpret_cast<HMODULE>(modules_data_deque[uiModuleIndex].lpModuleBaseAddr), modules_data_deque[uiModuleIndex].dwModuleSize);
				if (!lpFoundAddress) {
					return nullptr;
				}
				if (!(modules_data_deque[uiModuleIndex].lpHooksPostAllocationBase = VirtualAlloc(lpFoundAddress, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
					return nullptr;
				}
			}
			if (modules_data_deque[uiModuleIndex].wPostModuleAllocatedSize  + uiNeededSize > static_cast<WORD>(PAGE_SIZE - 1)) {
				return nullptr;
			}
			modules_data_deque[uiModuleIndex].wPostModuleAllocatedSize += uiNeededSize;
			return static_cast<LPBYTE>(modules_data_deque[uiModuleIndex].lpHooksPostAllocationBase) + modules_data_deque[uiModuleIndex].wPostModuleAllocatedSize - uiNeededSize;
		}
		case before_the_module: {
			if (!modules_data_deque[uiModuleIndex].lpHooksPostAllocationBase) {
				LPVOID lpFoundAddress = Scanner::get_adjacent_memory_backward_i32bit(reinterpret_cast<HMODULE>(modules_data_deque[uiModuleIndex].lpModuleBaseAddr));
				if (!lpFoundAddress) {
					return nullptr;
				}
				if (!(modules_data_deque[uiModuleIndex].lpHooksPostAllocationBase = VirtualAlloc(lpFoundAddress, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
					return nullptr;
				}
			}
			if (modules_data_deque[uiModuleIndex].wPreModuleAllocatedSize  + uiNeededSize > static_cast<WORD>(PAGE_SIZE - 1)) {
				modules_data_deque[uiModuleIndex].wPreModuleAllocatedSize += uiNeededSize;
				return static_cast<LPBYTE>(modules_data_deque[uiModuleIndex].lpHooksPreAllocationBase) - modules_data_deque[uiModuleIndex].wPreModuleAllocatedSize - uiNeededSize;
			}
			return nullptr;
		}
	}
	return nullptr;
}

HookingMemoryManager::~HookingMemoryManager() {
	size_t sSize = modules_data_deque.size();
	for (size_t i = NULL; i < sSize; i++) {
		if (modules_data_deque[i].lpHooksPostAllocationBase) {
			VirtualFree(modules_data_deque[i].lpHooksPostAllocationBase, PAGE_SIZE, MEM_FREE);
		}
		if (modules_data_deque[i].lpHooksPreAllocationBase) {
			VirtualFree(modules_data_deque[i].lpHooksPreAllocationBase, PAGE_SIZE, MEM_FREE);
		}
	}
}