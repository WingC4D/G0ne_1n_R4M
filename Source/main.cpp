#include <windows.h>
#include "hooking/manager.h"
#include "hooking/hook/tests.h"

int main() {
    hook::Manager manager;

    hook::Id message_box_a_id = manager.create(reinterpret_cast<const BYTE*>(MessageBoxA), HookedMessageBoxA, static_cast<const BYTE**>(reinterpret_cast<void*>(&g_MessageBoxA)));
    hook::Status result = manager.install(message_box_a_id);

    hook::Id create_file_w_id = manager.create(reinterpret_cast<const BYTE*>(CreateFileW), HookedCreateFileW, static_cast<const BYTE**>(reinterpret_cast<void*>(&g_CreateFileW)));
    result = manager.install(create_file_w_id);

    MessageBoxA(nullptr, "Woohoo!", "Caption", MB_OKCANCEL | MB_ICONQUESTION);

    return 0;
}