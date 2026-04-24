#ifdef _WIN32
#include <Windows.h>
#include <cstdint>
#include <thread>

static constexpr size_t INSTRUCTION_SIZE = 6;
static uint8_t  g_originalBytes[INSTRUCTION_SIZE] = {};
static void*    g_instructionPointer = nullptr;
static bool     g_patched = false;

constexpr uint8_t THIRD_PERSON_NAMETAG_SIG[] = {
    0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x45, 0x00, 0x49, 0x8B, 0xCD, 0x48, 0x8B, 0x80,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x84, 0xC0, 0x0F, 0x85
};

constexpr uint8_t THIRD_PERSON_NAMETAG_MASK[] = {
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
};

static uintptr_t FindPattern(uintptr_t base, size_t size,
                             const uint8_t* pattern, const uint8_t* mask, size_t patternLen) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(base);
    for (size_t i = 0; i < size - patternLen; ++i) {
        bool found = true;
        for (size_t j = 0; j < patternLen; ++j) {
            if (mask[j] == 0xFF && data[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return base + i;
    }
    return 0;
}

static void ApplyPatch() {
    if (!g_instructionPointer || g_patched) return;
    DWORD protect;
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, PAGE_EXECUTE_READWRITE, &protect);
    memset(g_instructionPointer, 0x90, INSTRUCTION_SIZE);
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, protect, &protect);
    g_patched = true;
}

static void RemovePatch() {
    if (!g_instructionPointer || !g_patched) return;
    DWORD protect;
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, PAGE_EXECUTE_READWRITE, &protect);
    memcpy(g_instructionPointer, g_originalBytes, INSTRUCTION_SIZE);
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, protect, &protect);
    g_patched = false;
}

static void Initialize() {
    HMODULE base = GetModuleHandleA(nullptr);
    if (!base) return;

    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(base) + dosHeader->e_lfanew);
    size_t sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

    uintptr_t targetAddr = FindPattern(
        reinterpret_cast<uintptr_t>(base), sizeOfImage,
        THIRD_PERSON_NAMETAG_SIG, THIRD_PERSON_NAMETAG_MASK,
        sizeof(THIRD_PERSON_NAMETAG_SIG));

    if (targetAddr) {
        g_instructionPointer = reinterpret_cast<void*>(targetAddr);
        memcpy(g_originalBytes, g_instructionPointer, INSTRUCTION_SIZE);
        ApplyPatch();
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        std::thread(Initialize).detach();
    } else if (reason == DLL_PROCESS_DETACH) {
        RemovePatch();
    }
    return TRUE;
}

#else
// ═══════════════════════════════════════════════════════════
//  ANDROID - ThirdPersonNametag + FPS/Ping display v3
//
//  FPS hook pakai 2 strategi fallback:
//  1. Vtable hook Actor slot getNameTag (tidak tergantung signature)
//  2. Signature scan multi-kandidat (toleran beda versi)
// ═══════════════════════════════════════════════════════════
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <atomic>
#include <chrono>
#include <sys/mman.h>

#include <android/log.h>
#include "pl/Gloss.h"
#include "pl/Signature.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "FPSNametag", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "FPSNametag", __VA_ARGS__)

static constexpr const char* MCPE_LIB = "libminecraftpe.so";

// ─────────────────────────────────────────────────────────
//  BAGIAN 1: ThirdPersonNametag (tidak diubah)
// ─────────────────────────────────────────────────────────

static const char* NAMETAG_SIGNATURE =
        "? ? 40 F9 "
        "? ? ? EB "
        "? ? ? 54 "
        "? ? 40 F9 "
        "? 81 40 F9 "
        "E0 03 ? AA "
        "00 01 3F D6 "
        "? ? 00 37 "
        "? ? 40 F9 "
        "? ? ? A9 "
        "? ? ? CB "
        "? ? ? D3 "
        "? ? 00 51 "
        "? ? ? 8A";

static constexpr size_t PATCH_OFFSET = 8;
static const uint8_t PATCH_BYTES[4] = { 0x1F, 0x20, 0x03, 0xD5 };
static const size_t  PATCH_SIZE     = sizeof(PATCH_BYTES);

static uint8_t g_originalBytes[PATCH_SIZE] = {};
static void*   g_patchTarget = nullptr;
static bool    g_isPatched   = false;

// Helper: scan memory untuk string/pattern
static uintptr_t scanMem(uintptr_t base, size_t sz, const void* pat, size_t plen) {
    auto* m = (const uint8_t*)base;
    auto* p = (const uint8_t*)pat;
    for (size_t i = 0; i+plen <= sz; ++i)
        if (memcmp(m+i, p, plen) == 0) return base+i;
    return 0;
}

static bool hookVtable(const char* cls, int slot, void** outOrig, void* hookFn) {
    size_t rodataSize = 0;
    uintptr_t rodata = GlossGetLibSection(MCPE_LIB, ".rodata", &rodataSize);
    if (!rodata || !rodataSize) { LOGE("hookVtable: no .rodata for %s", cls); return false; }

    uintptr_t zts = scanMem(rodata, rodataSize, cls, strlen(cls)+1);
    if (!zts) { LOGE("hookVtable: ZTS not found for %s", cls); return false; }

    size_t drrSize = 0;
    uintptr_t drr = GlossGetLibSection(MCPE_LIB, ".data.rel.ro", &drrSize);
    if (!drr || !drrSize) { LOGE("hookVtable: no .data.rel.ro for %s", cls); return false; }

    uintptr_t zti = 0;
    for (size_t i = 0; i+sizeof(uintptr_t) <= drrSize; i += sizeof(uintptr_t))
        if (*reinterpret_cast<uintptr_t*>(drr+i) == zts) { zti = drr+i-sizeof(uintptr_t); break; }
    if (!zti) { LOGE("hookVtable: ZTI not found for %s", cls); return false; }

    uintptr_t vtbl = 0;
    for (size_t i = 0; i+sizeof(uintptr_t) <= drrSize; i += sizeof(uintptr_t))
        if (*reinterpret_cast<uintptr_t*>(drr+i) == zti) { vtbl = drr+i+sizeof(uintptr_t); break; }
    if (!vtbl) { LOGE("hookVtable: VTable not found for %s", cls); return false; }

    void** vt = reinterpret_cast<void**>(vtbl);
    *outOrig = vt[slot];
    Unprotect(vtbl + slot*sizeof(void*), sizeof(void*));
    vt[slot] = hookFn;
    __builtin___clear_cache((char*)(vtbl+slot*sizeof(void*)), (char*)(vtbl+(slot+1)*sizeof(void*)));
    LOGI("hooked %s slot[%d]", cls, slot);
    return true;
}

static bool PatchMemory(void* addr, const void* data, size_t size) {
    uintptr_t page_start = (uintptr_t)addr & ~(4095UL);
    size_t    page_size  = ((uintptr_t)addr + size - page_start + 4095) & ~(4095UL);
    if (mprotect((void*)page_start, page_size, PROT_READ|PROT_WRITE|PROT_EXEC) != 0)
        return false;
    memcpy(addr, data, size);
    __builtin___clear_cache((char*)addr, (char*)addr + size);
    mprotect((void*)page_start, page_size, PROT_READ|PROT_EXEC);
    return true;
}

static bool PatchNametag() {
    uintptr_t addr = pl::signature::pl_resolve_signature(NAMETAG_SIGNATURE, MCPE_LIB);
    if (addr == 0) return false;
    g_patchTarget = reinterpret_cast<void*>(addr + PATCH_OFFSET);
    memcpy(g_originalBytes, g_patchTarget, PATCH_SIZE);
    if (PatchMemory(g_patchTarget, PATCH_BYTES, PATCH_SIZE)) {
        g_isPatched = true;
        return true;
    }
    return false;
}

static bool UnpatchNametag() {
    if (!g_patchTarget || !g_isPatched) return false;
    if (PatchMemory(g_patchTarget, g_originalBytes, PATCH_SIZE)) {
        g_isPatched = false;
        return true;
    }
    return false;
}

static void* g_VanillaCameraAPI_orig = nullptr;
using VanillaCameraAPI_t = int (*)(void*);

static int VanillaCameraAPI_hook(void* thisPtr) {
    int value = ((VanillaCameraAPI_t)g_VanillaCameraAPI_orig)(thisPtr);
    if (value != 0 && !g_isPatched) PatchNametag();
    if (value == 0 && g_isPatched)  UnpatchNametag();
    return value;
}

// ─────────────────────────────────────────────────────────
//  BAGIAN 2: FPS counter
// ─────────────────────────────────────────────────────────

static std::atomic<int> g_fps{0};
static std::atomic<int> g_ping{-1};

static int calcFPS() {
    using namespace std::chrono;
    static auto  lastTime  = steady_clock::now();
    static int   frames    = 0;
    static int   cached    = 0;
    frames++;
    auto now     = steady_clock::now();
    auto elapsed = duration_cast<milliseconds>(now - lastTime).count();
    if (elapsed >= 1000) {
        cached  = (int)(frames * 1000.0f / elapsed);
        frames  = 0;
        lastTime = now;
        g_fps.store(cached);
    }
    return g_fps.load();
}

// ─────────────────────────────────────────────────────────
//  BAGIAN 3: Hook getNameTag
// ─────────────────────────────────────────────────────────

using getNameTag_t = std::string* (*)(void*);
static void* g_orig_getNameTag = nullptr;
static thread_local std::string g_modifiedTag;

static std::string* hook_getNameTag(void* actor) {
    std::string* original = ((getNameTag_t)g_orig_getNameTag)(actor);
    if (!original || original->empty()) return original;

    int fps  = calcFPS();
    int ping = g_ping.load();

    char suffix[32];
    if (ping >= 0)
        snprintf(suffix, sizeof(suffix), " (%dms)", ping);
    else
        snprintf(suffix, sizeof(suffix), " (%dfps)", fps);

    g_modifiedTag = *original + suffix;
    return &g_modifiedTag;
}

// Strategi 1: vtable hook — tidak tergantung signature, lebih reliable
// Coba slot 59-63 (rentang getNameTag di berbagai versi MCBE ARM64)
static bool tryVtableHookGetNameTag() {
    size_t rodataSize = 0;
    uintptr_t rodata = GlossGetLibSection(MCPE_LIB, ".rodata", &rodataSize);
    if (!rodata || !rodataSize) return false;

    // Cari ZTS "5Actor"
    const char* cls = "5Actor";
    uintptr_t zts = scanMem(rodata, rodataSize, cls, strlen(cls)+1);
    if (!zts) { LOGE("vtableHook: ZTS 5Actor not found"); return false; }

    size_t drrSize = 0;
    uintptr_t drr = GlossGetLibSection(MCPE_LIB, ".data.rel.ro", &drrSize);
    if (!drr || !drrSize) return false;

    uintptr_t zti = 0;
    for (size_t i = 0; i+sizeof(uintptr_t) <= drrSize; i += sizeof(uintptr_t))
        if (*reinterpret_cast<uintptr_t*>(drr+i) == zts) { zti = drr+i-sizeof(uintptr_t); break; }
    if (!zti) { LOGE("vtableHook: ZTI not found"); return false; }

    uintptr_t vtbl = 0;
    for (size_t i = 0; i+sizeof(uintptr_t) <= drrSize; i += sizeof(uintptr_t))
        if (*reinterpret_cast<uintptr_t*>(drr+i) == zti) { vtbl = drr+i+sizeof(uintptr_t); break; }
    if (!vtbl) { LOGE("vtableHook: vtable not found"); return false; }

    // Coba slot 59-63, pakai GlossHook untuk trampolin aman
    void** vt = reinterpret_cast<void**>(vtbl);
    static const int slots[] = {61, 62, 60, 59, 63, 64, 58};
    for (int slot : slots) {
        void* fnPtr = vt[slot];
        if (!fnPtr) continue;

        void* orig = nullptr;
        // Gunakan GlossHook pada fungsi pointer dari vtable (lebih aman dari patch vtable langsung)
        if (GlossHook(fnPtr, (void*)hook_getNameTag, &orig) == 0) {
            g_orig_getNameTag = orig;
            LOGI("getNameTag: vtable slot[%d] GlossHook OK", slot);
            return true;
        }
    }
    LOGE("getNameTag: semua vtable slot gagal di-hook");
    return false;
}

// Strategi 2: signature scan multi-kandidat
static bool trySigScanGetNameTag() {
    static const char* sigs[] = {
        // MCBE 1.20.x - 1.21.x (paling umum)
        "F4 4F BE A9 "
        "FD 7B 01 A9 "
        "FD 43 00 91 "
        "F4 03 00 AA "
        "? ? 40 F9 "
        "? ? 40 F9",

        // Variasi 1: frame size berbeda
        "F6 57 BD A9 "
        "F4 4F 01 A9 "
        "FD 7B 02 A9 "
        "FD 83 00 91 "
        "F4 03 00 AA "
        "? ? 40 F9",

        // Variasi 2: prologue wildcard lebih banyak
        "? ? BE A9 "
        "FD 7B ? A9 "
        "FD ? 00 91 "
        "F4 03 00 AA "
        "? ? 40 F9 "
        "? ? 40 F9 "
        "? ? 40 F9",

        // MCBE 1.19.x
        "F4 4F BE A9 "
        "FD 7B 01 A9 "
        "FD 43 00 91 "
        "F4 03 00 AA "
        "? ? 40 F9",

        nullptr
    };

    for (int i = 0; sigs[i]; ++i) {
        uintptr_t addr = pl::signature::pl_resolve_signature(sigs[i], MCPE_LIB);
        if (!addr) { LOGI("sig[%d] not found", i); continue; }

        void* orig = nullptr;
        if (GlossHook((void*)addr, (void*)hook_getNameTag, &orig) == 0) {
            g_orig_getNameTag = orig;
            LOGI("getNameTag: sig[%d] hooked OK", i);
            return true;
        }
        LOGE("getNameTag: sig[%d] found but GlossHook failed", i);
    }
    return false;
}

// ─────────────────────────────────────────────────────────
//  ENTRY POINT
// ─────────────────────────────────────────────────────────
__attribute__((constructor))
void ThirdPersonNametag_Init() {
    GlossInit(true);

    // ThirdPersonNametag asli
    hookVtable("16VanillaCameraAPI", 7,
               &g_VanillaCameraAPI_orig,
               (void*)VanillaCameraAPI_hook);

    if (!g_isPatched) PatchNametag();

    // FPS hook: vtable dulu, fallback sig scan
    bool fpsOK = tryVtableHookGetNameTag();
    if (!fpsOK) {
        LOGI("vtable hook gagal, coba sig scan...");
        fpsOK = trySigScanGetNameTag();
    }

    if (fpsOK)
        LOGI("FPS display ON");
    else
        LOGE("FPS display OFF - nametag tetap jalan normal");

    LOGI("FPSNametag v3 ready!");
}

__attribute__((destructor))
void ThirdPersonNametag_Shutdown() {
    if (g_isPatched) UnpatchNametag();
}

#endif
