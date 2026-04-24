#pragma once
#include <windows.h>
#include <winternl.h>
#include <vector>
#include "hooking/constansts.h"

namespace hook {
    namespace memory {
        struct Handler {
            struct ModuleContext {
                BYTE* base;
                DWORD size,
                      preAllocatedSize  = 0,
                      postAllocatedSize = 0;
                BYTE* preAllocation     = nullptr,
                    * postAllocation    = nullptr;
            };

            std::vector<ModuleContext>modules;

            Handler() {
                modules.reserve(sizes::MAX_MODULES);

                mapModules();

                modules.shrink_to_fit();
            }

            AllocationResult allocateGateways(const BYTE* target_function, BYTE buffer_size);

            BYTE* allocatePreModuleBuffer(const BYTE* target_function, Index idx, BYTE buffer_size);

            BYTE* allocatePostModuleBuffer(const BYTE* target_function, Index idx, BYTE buffer_size);

        private:
            Index findModuleByFunction(const void* function_address);

            void addModule(const _LDR_DATA_TABLE_ENTRY* table_entry);

            void mapModules() {
                LIST_ENTRY* list_head     = reinterpret_cast<PEB*>(__readgsqword(0x60))->Ldr->InMemoryOrderModuleList.Flink,
                          * current_entry = list_head;
                do {
                    addModule(reinterpret_cast<_LDR_DATA_TABLE_ENTRY*>(current_entry));
                    current_entry = current_entry->Flink;
                } while (list_head != current_entry);
            }

            [[nodiscard]] static DWORD getModuleSize(const void* module_base) {
                if (!module_base)
                    return 0;

                if (static_cast<const IMAGE_DOS_HEADER*>(module_base)->e_magic != IMAGE_DOS_SIGNATURE)
                    return 0;

                if (reinterpret_cast<const IMAGE_NT_HEADERS*>(static_cast<const BYTE*>(module_base) + static_cast<const IMAGE_DOS_HEADER*>(module_base)->e_lfanew)->Signature != IMAGE_NT_SIGNATURE)
                    return 0;

                return reinterpret_cast<const IMAGE_NT_HEADERS*>(static_cast<const BYTE*>(module_base) + static_cast<const IMAGE_DOS_HEADER*>(module_base)->e_lfanew)->OptionalHeader.SizeOfImage;
            }
        };
    }
}