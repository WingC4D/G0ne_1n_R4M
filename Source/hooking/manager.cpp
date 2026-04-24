#include "hooking/manager.h"
using namespace hook;

Id Manager::create(const BYTE* target, const void *detour, LPCBYTE * original) { using namespace sizes;
    if (!target || !detour || !original)
        return INVALID_ID;

    if (lde.resolveHookSize(reinterpret_cast<const void*&>(target)) != LdeState::success)
        return INVALID_ID;

    auto allocation_result = memoryHandler.allocateGateways(target, 2 * ABSOLUTE_TRAMPOLINE + lde.trackedSize);

    if (!allocation_result.buffer)
        return INVALID_ID;

    contextsVec.emplace_back(const_cast<BYTE *>(target), static_cast<LPCBYTE>(detour), allocation_result.buffer, allocation_result.idx, lde.trackedSize, numberOfHooks++, lde);
    lde = LdeState{};
    if (contextsVec.back().id == INVALID_ID) {
        contextsVec.pop_back();
        return INVALID_ID;
    }
    *original = contextsVec.back().originalFunction;

    return contextsVec.back().id;
}

Status Manager::install(Id hook_id) const {
    if (*contextsVec[hook_id].trampolinesBuffer)
        return hook_already_active;

    contextsVec[hook_id].createGateways();
    DWORD old_protections   = 0,
          applied_protections = PAGE_READWRITE;
    BYTE swap_size = 0;
    if (!VirtualProtect(contextsVec[hook_id].trampolinesBuffer, static_cast<QWORD>(2 * sizes::ABSOLUTE_TRAMPOLINE) + contextsVec[hook_id].hookSize, PAGE_EXECUTE_READ, &old_protections))
        return memory_protections_edit_failed;

    
    switch (swap_size = contextsVec[hook_id].getExchangeSize()) { using namespace sizes;
        case 0x08: {
            BYTE trampoline[0x08]{ inst::opcodes::JUMP };
            *reinterpret_cast<int*>(&trampoline[1]) = contextsVec[hook_id].calculateDisposition();

            if (!contextsVec[hook_id].generateNOPs(trampoline,  RELATIVE_TRAMPOLINE))
                return hook_size_calc_failed;

            if (memcpy_s(&trampoline[contextsVec[hook_id].hookSize], 8 - contextsVec[hook_id].hookSize, contextsVec[hook_id].target + contextsVec[hook_id].hookSize, 8- contextsVec[hook_id].hookSize))
                return hook_size_calc_failed;

            if (!VirtualProtect(contextsVec[hook_id].target, 0x08, applied_protections, &old_protections))
                return memory_protections_edit_failed;

            _InterlockedCompareExchange64(reinterpret_cast<long long volatile *>(contextsVec[hook_id].target), *reinterpret_cast<long long *>(&trampoline[0]), *reinterpret_cast<long long*>(contextsVec[hook_id].target));

            if (!VirtualProtect(contextsVec[hook_id].target, 0x08, old_protections, &applied_protections)) {
                _InterlockedCompareExchange64(reinterpret_cast<long long volatile*>(contextsVec[hook_id].target), *static_cast<long long*>(contextsVec[hook_id].retrieveOriginalBytes()), *reinterpret_cast<long long*>(contextsVec[hook_id].target));

                if (!VirtualProtect(contextsVec[hook_id].target, 0x08, applied_protections, &old_protections))
                    return memory_protections_edit_failed;
            }
            break;
        }
        case 0x10:
            if (!VirtualProtect(contextsVec[hook_id].target, swap_size, applied_protections, &old_protections))
                return memory_protections_edit_failed;
            break;

        case 0x18:
            break;


        default:
            return hook_size_calc_failed;

    }
    return success;
}
