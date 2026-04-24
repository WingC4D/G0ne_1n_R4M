#pragma once
#include <vector>
#include "hook/context.h"
#include "hooking/memory_handler.h"

namespace hook {
    class Manager {
        LdeState lde{};
        std::vector<Context> contextsVec{};
        Id                   numberOfHooks = 0;
        memory::Handler      memoryHandler{};

    public:
        [[nodiscard]] Id     create(const BYTE* target, const void* detour, const BYTE** original);

        [[nodiscard]] Status install(Id hook_id) const;

    };
}

