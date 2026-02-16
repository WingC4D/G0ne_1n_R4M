#pragma once

#include <windows.h>
#include <deque>
#include "Scanner.h"

constexpr hkUINT   INVALID_MODULE_INDEX	  = 0xFFFFFFFF;
constexpr LONGLONG TWO_GIGABYTES		  = 0x80000000;

typedef struct HOOKS_MODULE_DATA {
	LPBYTE					lpModuleBaseAddr;
	PLDR_DATA_TABLE_ENTRY	pModuleLDR;
	PIMAGE_EXPORT_DIRECTORY pModuleExportDir;
	DWORD				    dwModuleSize;
	WORD					wPostModuleAllocatedSize,
							wPreModuleAllocatedSize;
	LPVOID					lpHooksPostAllocationBase,
							lpHooksPreAllocationBase;
}*HOOKS_MODULE_DATA_PTR;

enum optimal_hook_location: BYTE {
	after_the_module,
	before_the_module,
	unknown
};

class HookingMemoryManager {
public:
	HookingMemoryManager(Scanner& scanner_ref);

	Scanner* scanner;

	std::deque<HOOKS_MODULE_DATA> modules_data_deque;// = std::deque<HOOKS_MODULE_DATA>(NULL);

	LPVOID get_adjacent_virtual_buffer(LPVOID lpTargetAddress, WORD uiNeededSize);

	HMODULE get_local_module_handle_by_function(LPVOID lpFunctionAddress) const;

	hkUINT get_local_module_index_by_function(LPVOID lpFunctionAddress) const;

	optimal_hook_location check_where_to_place_hook_by_function(LPVOID lpTargetFunction) const;

	optimal_hook_location check_where_to_place_hook_by_index(LPVOID lpTargetFunction, hkUINT uiIndex) const;
private:
	inline void map_all_local_modules() ;
};

