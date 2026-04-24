#include "hooking/hook/context.h"
using namespace hook;

void Context::createGateways() const { using namespace assembly; using namespace sizes;
    *reinterpret_cast<WORD*>(trampolinesBuffer)                                                                        = MOV_R10;
    *reinterpret_cast<DWORD*>(trampolinesBuffer + MOVE_64BIT_REG + sizeof(detour) - 1)                                 = JMP_R10;
    *reinterpret_cast<const void**>(trampolinesBuffer + MOVE_64BIT_REG)                                                = detour;
    *reinterpret_cast<WORD*>(trampolinesBuffer + ABSOLUTE_TRAMPOLINE + hookSize)                                       = MOV_R10;
    *reinterpret_cast<DWORD*>(trampolinesBuffer + ABSOLUTE_TRAMPOLINE + hookSize + MOVE_64BIT_REG + sizeof(void*) - 1) = JMP_R10;
    *reinterpret_cast<const void**>(trampolinesBuffer + ABSOLUTE_TRAMPOLINE + hookSize + MOVE_64BIT_REG)               = target + hookSize;
    for (BYTE i = 0; i < hookSize; i++)
        trampolinesBuffer[ABSOLUTE_TRAMPOLINE + i] = target[i];
}

long Context::calculateDisposition() const {
    return static_cast<long>(trampolinesBuffer - target - sizes::RELATIVE_TRAMPOLINE);
}

BOOLEAN Context::generateNOPs(BYTE buffer[], const BYTE jump_size) const {
    switch (hookSize - jump_size) {
        case 0:
            break;
        case 1:
            buffer[jump_size] = 0x90;
            break;
        case 2:
            *reinterpret_cast<WORD*>(&buffer[jump_size])  = 0x9066;
            break;
        case 3:
            *reinterpret_cast<WORD*>(&buffer[jump_size])  = 0x1F0F;
            break;
        case 4:
            *reinterpret_cast<DWORD*>(&buffer[jump_size]) = 0x401F0F;
            break;
        case 5:
            *reinterpret_cast<DWORD*>(&buffer[jump_size]) = 0x441F0F;
            break;
        case 6:
            *reinterpret_cast<DWORD*>(&buffer[jump_size]) = 0x66441F0F;
            break;
        case 7:
            buffer[jump_size] = 0x90;
            *reinterpret_cast<DWORD*>(&buffer[jump_size + 1]) = 0x441F0F;
            break;
        default:
            return false;
    }
    return true;
}

BOOLEAN Context::findAndFixRelocations() const {
    if (!trampolinesBuffer)
        return false;

    if (!lde.ripRelativeIdxCount)
        return true;

    for (BYTE rip_rel_idx = 0, general_idx = 0, accumulated_length = 0; general_idx < lde.instruction_count; general_idx++) {
        if (general_idx != lde.ripRelativeIndexes[rip_rel_idx]) {
            accumulated_length += lde.contextArray[general_idx].getLength();
            continue;
        }
        BYTE* old_target = target + accumulated_length + lde.contextArray[general_idx].getLength() +
            *reinterpret_cast<int*>(target + accumulated_length + lde.contextArray[general_idx].getPreDisposition());

        long long new_disposition = old_target - (trampolinesBuffer + accumulated_length + lde.contextArray[general_idx].getLength());

        if ((new_disposition & 0xFFFFFFFF00000000) != 0xFFFFFFFF00000000 && new_disposition & 0xFFFFFF00000000)
            return false;

        *reinterpret_cast<long*>(trampolinesBuffer + accumulated_length + lde.contextArray[general_idx].getPreDisposition()) = static_cast<long>(new_disposition);

        rip_rel_idx++;
    }

    return true;
}
