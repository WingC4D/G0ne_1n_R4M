#include "hooking/hook/lde_state.h"
using namespace hook;
using LPCBYTE = const unsigned char*;

LdeState::Status LdeState::resolveHookSize(const void*& target_function) {
    using namespace sizes; using namespace iat;
    if (!target_function)
        return no_input;

    switch (checkForIAT(static_cast<LPCBYTE>(target_function))) {
    case no_IAT:
        prepareForNextStep();
        break;
    case has_IAT:
        target_function = reinterpret_cast<const BYTE*>(handleIAT(static_cast<LPCBYTE>(target_function)));
        break;
    case CheckResult::no_input:
        return no_input;
    case failed:
        return hook_size_calc_failed;
    }

    while (trackedSize < RELATIVE_TRAMPOLINE && instruction_count < RELATIVE_TRAMPOLINE) { using enum inst::Context::Status;
        if ((status = currContext.map(static_cast<LPCBYTE>(target_function) + trackedSize)) != success && status != reached_end_of_function)
            return hook_size_calc_failed;

        currContext.analyseOpcodeType(static_cast<LPCBYTE>(target_function) + trackedSize);
        prepareForNextStep();

    }
    if (trackedSize < RELATIVE_TRAMPOLINE && instruction_count == RELATIVE_TRAMPOLINE)
        return hook_size_calc_failed;
    return success;
}

iat::CheckResult LdeState::checkForIAT(const BYTE* target_function) { using namespace iat;
    using enum inst::Context::Status;
    if (!target_function)
        return CheckResult::no_input;

    if ((status = currContext.map(target_function + trackedSize)) != success && status != reached_end_of_function)
        return failed;

    switch (currContext.analyseOpcodeType(target_function)) { using enum inst::opcodes::Types;
        case indirect_call:
        case call:
        case indirect_jump:
            return has_IAT;

        default:
            return no_IAT;
    }
}