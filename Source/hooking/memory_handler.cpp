#include "hooking/memory_handler.h"

#include <print>

using namespace hook::memory;

AllocationResult Handler::allocateGateways(const BYTE* target_function, BYTE buffer_size) { using namespace hook::sizes;
    if (!buffer_size || !target_function)
        return AllocationResult{ .buffer = nullptr, .idx = INVALID_INDEX };

    AllocationResult result{ .idx = findModuleByFunction(target_function) };

    if (result.idx == INVALID_INDEX)
        return result;

    if (!modules[result.idx].preAllocation && target_function - modules[result.idx].base - PAGE < TWO_GB) {
        result.buffer = allocatePreModuleBuffer(target_function, result.idx, buffer_size);
        return result.buffer ? result : AllocationResult{ .buffer = nullptr, .idx = INVALID_INDEX };
    }

    if (modules[result.idx].preAllocatedSize + buffer_size < PAGE && target_function - modules[result.idx].preAllocation + modules[result.idx].preAllocatedSize + buffer_size < TWO_GB) {
        result.buffer = modules[result.idx].preAllocation + modules[result.idx].preAllocatedSize;
        modules[result.idx].postAllocatedSize += buffer_size;
        return result;
    }

    if (!modules[result.idx].postAllocation) {
        result.buffer = allocatePostModuleBuffer(target_function, result.idx, buffer_size);
        return result.buffer ? result : AllocationResult{ .buffer = nullptr, .idx = INVALID_INDEX };
    }

    if (modules[result.idx].postAllocatedSize + buffer_size < PAGE) {
        result.buffer = modules[result.idx].postAllocation + modules[result.idx].postAllocatedSize;
        modules[result.idx].postAllocatedSize += buffer_size;
        return result;
    }

    return AllocationResult{ .buffer = nullptr, .idx = INVALID_INDEX };
}

Index Handler::findModuleByFunction(const void* function_address) { using namespace hook::memory;
    WORD module_index = 0;
    for (std::vector<ModuleContext>::iterator it_beginning = modules.begin(), it_ending = --modules.end(), last_end = it_ending; it_beginning != last_end && it_beginning != modules.end(); 
        ++it_beginning, --it_ending) {

        if (it_beginning->base < function_address)
            if (function_address < it_beginning->base + it_beginning->size)
                return module_index;

        if (it_ending->base < function_address)
            if (function_address < it_ending->base + it_ending->size)
                return static_cast<Index>(modules.size() - ++module_index);

        last_end = it_ending;
        module_index++;
    }
    return INVALID_INDEX;
}

BYTE* Handler::allocatePostModuleBuffer(const BYTE* target_function, const Index idx, BYTE buffer_size) { using namespace hook::sizes;
    MEMORY_BASIC_INFORMATION memory_basic_info;
    WORD                     i = 0;
    while (i < MAX_ITERATIONS && modules[idx].base + modules[idx].size + static_cast<QWORD>(i * PAGE) - target_function < TWO_GB) {
        if (!VirtualQuery(modules[idx].base + static_cast<QWORD>(modules[idx].size + i * PAGE), &memory_basic_info, PAGE))
            continue;
        if (memory_basic_info.State == MEM_FREE) {
            modules[idx].postAllocation = static_cast<BYTE*>(VirtualAlloc(modules[idx].base + modules[idx].size + static_cast<QWORD>(i * PAGE), PAGE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (!modules[idx].postAllocation)
                return nullptr;

            if (modules[idx].postAllocation - target_function < TWO_GB) {
                VirtualFree(modules[idx].postAllocation, PAGE, MEM_FREE);
                modules[idx].postAllocation = nullptr;
            }
            modules[idx].postAllocatedSize += buffer_size;
            return modules[idx].postAllocation;
        }
        i++;
    }
    return  nullptr;
}

BYTE* Handler::allocatePreModuleBuffer(const BYTE* target_function, const Index idx, BYTE buffer_size) { using namespace hook::sizes;
    MEMORY_BASIC_INFORMATION memory_basic_info;
    WORD                     i = 1;
    while (i < MAX_ITERATIONS && target_function - modules[idx].base - static_cast<QWORD>(i * PAGE) < TWO_GB) {
        if (!VirtualQuery(modules[idx].base - static_cast<QWORD>(i * PAGE), &memory_basic_info, sizeof(MEMORY_BASIC_INFORMATION))) {
            i++;
            continue;
        }
        if (memory_basic_info.State == MEM_FREE && !memory_basic_info.Type) {
            if (memory_basic_info.Protect != PAGE_GUARD)
                modules[idx].preAllocation = static_cast<BYTE*>(VirtualAlloc(memory_basic_info.BaseAddress, 0x100, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            else {
                i++;
                continue;
            }
            if (!modules[idx].preAllocation) {
                std::println("[!] VirtualAlloc Failed with error code: {:#010x}", GetLastError());
                i++;
                continue;
            }
            if (target_function - modules[idx].preAllocation > TWO_GB) {
                VirtualFree(modules[idx].preAllocation, PAGE, MEM_FREE);
                modules[idx].preAllocation = nullptr;
            }
            modules[idx].preAllocatedSize += buffer_size;
            return modules[idx].preAllocation;
        }
        i++;
    }
    return nullptr;
}

void Handler::addModule(const _LDR_DATA_TABLE_ENTRY* table_entry) {
    if (!table_entry->Reserved2[0])
        return;
    for (auto it = modules.begin(); it != modules.end(); ++it) {
        if (it->base > table_entry->Reserved2[0]) {
            DWORD size = getModuleSize(table_entry->Reserved2[0]);
            if (!size)
                return;
            modules.emplace(it, static_cast<BYTE*>(table_entry->Reserved2[0]), size);
            return;
        }
    }
    DWORD size = getModuleSize(table_entry->Reserved2[0]);
    if (!size)
        return;

    modules.emplace_back(static_cast<BYTE*>(table_entry->Reserved2[0]), size);
}
