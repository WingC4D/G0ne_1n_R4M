#pragma once
#include "disassembly/lde_common.h"
#include "hooking/constansts.h"
namespace hook {
    struct LdeState : LdeCommon {
        enum Status : unsigned char {
            success,
            no_input,
            wrong_input,
            hook_size_calc_failed
        };
        inst::Context contextArray[sizes::RELATIVE_TRAMPOLINE]{};
        BYTE          ripRelativeIndexes[sizes::RELATIVE_TRAMPOLINE]{},
                      ripRelativeIdxCount = 0,
                      trackedSize = 0;
        Status           resolveHookSize(const void*& target_function);
        iat::CheckResult checkForIAT(const BYTE* target_function);

        const BYTE* handleIAT(const BYTE* target_function) {
            const BYTE* result = currContext.resolveJump(target_function);
            currContext.clear();
            return result;
        }

        void prepareForNextStep() {
            if (currContext.isRipRelative())
                ripRelativeIndexes[ripRelativeIdxCount++] = instruction_count;
            trackedSize += currContext.getLength();
            contextArray[instruction_count++] = currContext;
            currContext.clear();
        }
    };
}