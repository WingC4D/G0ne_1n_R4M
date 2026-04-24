#pragma once
#include "hooking/constansts.h"
#include "lde_state.h"
namespace hook {
    struct Context {
        const BYTE   *detour,
                     *originalFunction;
        BYTE          hookSize          = 0,
                     *trampolinesBuffer = nullptr,
                     *target            = nullptr;  
        Id            id = INVALID_ID;
        memory::Index moduleIdx = memory::INVALID_INDEX;
        LdeState lde{};

        void* retrieveOriginalBytes() const {
            if (!trampolinesBuffer)
                return nullptr;
            return &trampolinesBuffer[sizes::ABSOLUTE_TRAMPOLINE];
        }

        void createGateways() const;

        long calculateDisposition() const;

        BOOLEAN generateNOPs(BYTE buffer[], BYTE jump_size) const;

        BOOLEAN findAndFixRelocations() const;

        BYTE getExchangeSize() const {
            if (hookSize <= 8)
                return 8;
            return hookSize <= 0x10 ? 0x10 : 0x18;
        }

        Context(void* target_func, const BYTE* detour_address, BYTE* trampolines, memory::Index module_index, BYTE hook_size, Id hook_id, const LdeState& lde):
        detour(detour_address),
        originalFunction(trampolines + sizes::ABSOLUTE_TRAMPOLINE) {
            trampolinesBuffer = trampolines;
            if (!trampolinesBuffer) 
                return;
            
            target = static_cast<BYTE*>(target_func);

            if (!target) 
                return;
            

            hookSize = hook_size;
            if (!hookSize)
                return;

            if (module_index == memory::INVALID_INDEX) 
                return;
            
            moduleIdx = module_index;
            id        = hook_id;
            this->lde = lde;
        }
    };
}