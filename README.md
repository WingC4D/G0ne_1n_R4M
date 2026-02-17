# G0ne_1n_R4M

A Custom, Dependency-Free Dynamic Hooking Framework for Windows x64.

## Used Technologies

<p align="center"> 
  <a href="https://skillicons.dev">
    <img src="https://skillicons.dev/icons?i=cpp,visualstudio,windows,py,vscode"/>
  </a>
</p>

### Overview

This repository aims to house a research-grade API hooking engine built from scratch to explore low-level Windows internals, memory management, and defense-evasion techniques.

> [!NOTE]
> The primary goal of this project was to eliminate reliance on public hooking libraries (such as [MinHook](https://github.com/TsudaKageyu/minhook), [PolyHook](https://github.com/stevemk14ebr/PolyHook_2_0), or [Detours](https://github.com/microsoft/Detours) and disassembly engines (such as [Zydis](https://github.com/zyantific/zydis) or [Capstone](https://github.com/capstone-engine/capstone)), which often carry static signatures flagged by EDR solutions. Instead, **G0ne_1n_R4M** implements a proprietary Length Disassembly Engine (LDE) and a stateless hooking architecture to maintain a minimal memory footprint and avoid detection.

## Disclaimer

> [!IMPORTANT]
> This software is provided for educational and research purposes only. It is designed to demonstrate techniques used in offensive security and malware analysis. The author is not responsible for any misuse of this code.

> [!CAUTION]
> Do not misuse this software, as it could lead to criminal repercussions with your local authorities. Always ensure you have full consent before using any offensive cybersecurity-related software.

## Core Components

### 1. Custom Length Disassembly Engine (LDE)

A lightweight, stateless x64 instruction length decoder.

- **Architecture:** Implemented as a utility class (`LDE.cpp`, `LDE.h`) to ensure thread safety without the overhead of per-object instantiation.
- **Capabilities:**
	1. **Accurate parsing of variable-length x64 instructions**, including legacy prefixes (`0x66`, `0x67`), `REX` prefixes, and `ModR/M` bytes.
    2. **Relocation Fixing:** Automatically calculates and corrects RIP-relative displacements when instructions are moved to a trampoline (`find_n_fix_relocation`), preventing execution crashes common in naive hooking implementations.
    3. **Signature Evasion:** Uses a custom, obfuscated opcode lookup table rather than standard open-source tables.

### 2. Dynamic Hooking Engine (`HookManager`)

An inline hooking engine designed for stability and concurrency.

- **Trampoline Generation:** detailed analysis of target function preludes to generate safe, non-destructive trampolines.
- **Memory Management:** Utilizes a custom scanner to identify code caves (executable memory gaps) adjacent to target modules (within +/- 2GB) to allow for 5-byte relative jumps (`JMP Rel32`) instead of requiring 14-byte absolute jumps.
- **Deque-Based Storage:** Implements `std::deque` for hook context storage to prevent iterator invalidation and pointer corruption during runtime vector resizing (the "Split-Brain" problem).
- **Atomic Operations:** Ensures hooks can be installed and uninstalled cleanly without race conditions.

### 3. PE & Memory Scanner (`Scanner`)

A custom PE parser and memory walker that avoids standard WinAPI calls (`GetProcAddress`, `GetModuleHandle`).

- **PEB Walking:** Manually traverses the Process Environment Block (PEB) and `LDR_DATA_TABLE_ENTRY` to resolve module bases.
- **Manual Export Parsing:** Parses the Export Directory directly to resolve function addresses by hash, bypassing IAT hooks and standard API monitoring.
- **Page Scanning:** Iterates memory pages to find valid injection points that align with allocation granularity.

## Technical Highlights

- **Zero External Dependencies:** Built using only standard C++ and Windows headers.
- **Stateless LDE:** The LDE context is stack-allocated per call, ensuring thread safety for concurrent hook creation.
- **Correctness:** Handles edge cases such as finding memory regions within the 32-bit relative displacement limit of the target function.

## Usage

This framework is intended to be compiled as a static library or included directly into a loader project.

``` cpp
// Example Usage
HookManager hookMgr(GetCurrentProcess());
HOOK_CONTEXT hookCtx;

hookCtx.lpTargetFunc  = &MessageBoxA;       // Address of function to hook
hookCtx.lpDetourFunc  = &HookedMessageBoxA; // Address of your detour
hookCtx.lpOrgFuncAddr = &g_MessageBoxA;     // Pointer to receive the trampoline

// 1. Analyze and prepare the trampoline
hookMgr.CreateLocalHook(&hookCtx, &hookID);

// 2. Install the hook (modify memory permissions and write JMP)
hookMgr.install_hook(hookID);

// 3. Uninstall the hook (modify the memory space back to its original state)
hookMgr.uninstall_hook(hookID);
```

### To Do List

- [x] Refactor the `prefix` case.
- [ ] Implement Control Flow Graph Tracing
- [ ] Port the symbolic execution engine found in my [IDAPython Deobfuscation Script](https://github.com/WingC4D/IDA-Execution-Flow-Deobfuscating-Script) into this logic to be able to indirectly call stolen `SYSCALL` stubs.
