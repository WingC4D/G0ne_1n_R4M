#pragma once
#include "independent_types.h"
namespace hook {
    using               Id         = WORD;
    inline constexpr Id INVALID_ID = 0xFFFF;
    enum Status : BYTE {
        success,
        no_input,
        wrong_input,
        hook_size_calc_failed,
        hook_already_active,
        hook_already_inactive,
        memory_protections_edit_failed
    };
    namespace iat {
        enum CheckResult : BYTE {
            no_IAT,
            has_IAT,
            no_input,
            failed
        };
    }

    namespace assembly {
        inline constexpr WORD  MOV_R10 = 0xBA49;
        inline constexpr DWORD JMP_R10 = 0xE2FF4100;
    }

    namespace sizes{
        inline constexpr BYTE  MOVE_64BIT_REG      = 0x02,
                               RELATIVE_TRAMPOLINE = 0x05,
                               ABSOLUTE_TRAMPOLINE = 0x0D;
        inline constexpr WORD  MAX_MODULES         = 0x0200,//That I currently handle.
                               MAX_ITERATIONS      = 0x8000;
        inline constexpr DWORD PAGE                = 0x00001000,
                               TWO_GB              = 0x80000000;
    }

        namespace memory {
        using                  Index         = WORD;
        inline constexpr Index INVALID_INDEX = 0xFFFE;
        struct    AllocationResult {
            BYTE* buffer;
            Index idx;
        };
    }
}
