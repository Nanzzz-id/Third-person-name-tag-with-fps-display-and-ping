#ifdef _WIN32
#include <Windows.h>
#include <cstdint>
#include <thread>

static constexpr size_t INSTRUCTION_SIZE = 6;
static uint8_t  g_originalBytes[INSTRUCTION_SIZE] = {};
static void*    g_instructionPointer = nullptr;
static bool     g_patched = false;

constexpr uint8_t THIRD_PERSON_NAMETAG_SIG[] = {
    0x0F,0x84,0x00,0x00,0x00,0x00,0x49,0x8B,0x45,0x00,0x49,0x8B,0xCD,0x48,0x8B,0x80,
    0x00,0x00,0x00,0x00,0xFF,0x15,0x00,0x00,0x00,0x00,0x84,0xC0,0x0F,0x85
};
constexpr uint8_t THIRD_PERSON_NAMETAG_MASK[] = {
    0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x00,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF
};

static uintptr_t FindPattern(uintptr_t base, size_t size, const uint8_t* pat, const uint8_t* mask, size_t len) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(base);
    for (size_t i = 0; i < size - len; ++i) {
        bool found = true;
        for (size_t j = 0; j < len; ++j)
            if (mask[j] == 0xFF && data[i+j] != pat[j]) { found = false; break; }
        if (found) return base + i;
    }
    return 0;
}
static void ApplyPatch() {
    if (!g_instructionPointer || g_patched) return;
    DWORD p; VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, PAGE_EXECUTE_READWRITE, &p);
    memset(g_instructionPointer, 0x90, INSTRUCTION_SIZE);
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, p, &p);
    g_patched = true;
}
static void RemovePatch() {
    if (!g_instructionPointer || !g_patched) return;
    DWORD p; VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, PAGE_EXECUTE_READWRITE, &p);
    memcpy(g_instructionPointer, g_originalBytes, INSTRUCTION_SIZE);
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, p, &p);
    g_patched = false;
}
static void Initialize() {
    HMODULE base = GetModuleHandleA(nullptr); if (!base) return;
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto nt  = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(base) + dos->e_lfanew);
    uintptr_t addr = FindPattern(reinterpret_cast<uintptr_t>(base), nt->OptionalHeader.SizeOfImage,
        THIRD_PERSON_NAMETAG_SIG, THIRD_PERSON_NAMETAG_MASK, sizeof(THIRD_PERSON_NAMETAG_SIG));
    if (addr) {
        g_instructionPointer = reinterpret_cast<void*>(addr);
        memcpy(g_originalBytes, g_instructionPointer, INSTRUCTION_SIZE);
        ApplyPatch();
    }
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(hModule); std::thread(Initialize).detach(); }
    else if (reason == DLL_PROCESS_DETACH) RemovePatch();
    return TRUE;
}

#else
// ═══════════════════════════════════════════════════════════
//  ANDROID - ThirdPersonNametag + FPS display v6
//
//  Fix utama dari v5:
//  - Return type getNameTag yang benar: std::string const& (bukan std::string*)
//    Sumber: MinecraftHeaders/Actor/Actor.h baris 292
//  - Hook via GlossHook pada sig scan
//  - Kalau sig tidak match: nametag NORMAL, tidak crash
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
    "? ? 40 F9 ? ? ? EB ? ? ? 54 ? ? 40 F9 ? 81 40 F9 "
    "E0 03 ? AA 00 01 3F D6 ? ? 00 37 ? ? 40 F9 "
    "? ? ? A9 ? ? ? CB ? ? ? D3 ? ? 00 51 ? ? ? 8A";

static constexpr size_t PATCH_OFFSET = 8;
static const uint8_t PATCH_BYTES[4] = {0x1F,0x20,0x03,0xD5};
static uint8_t g_origBytes[4] = {};
static void*   g_patchTarget  = nullptr;
static bool    g_isPatched    = false;

static bool PatchMemory(void* addr, const void* data, size_t size) {
    uintptr_t ps = (uintptr_t)addr & ~4095UL;
    size_t    pz = ((uintptr_t)addr + size - ps + 4095) & ~4095UL;
    if (mprotect((void*)ps, pz, PROT_READ|PROT_WRITE|PROT_EXEC)) return false;
    memcpy(addr, data, size);
    __builtin___clear_cache((char*)addr, (char*)addr+size);
    mprotect((void*)ps, pz, PROT_READ|PROT_EXEC);
    return true;
}
static bool PatchNametag() {
    uintptr_t addr = pl::signature::pl_resolve_signature(NAMETAG_SIGNATURE, MCPE_LIB);
    if (!addr) return false;
    g_patchTarget = reinterpret_cast<void*>(addr + PATCH_OFFSET);
    memcpy(g_origBytes, g_patchTarget, 4);
    if (PatchMemory(g_patchTarget, PATCH_BYTES, 4)) { g_isPatched = true; return true; }
    return false;
}
static bool UnpatchNametag() {
    if (!g_patchTarget || !g_isPatched) return false;
    if (PatchMemory(g_patchTarget, g_origBytes, 4)) { g_isPatched = false; return true; }
    return false;
}

static uintptr_t scanMem(uintptr_t base, size_t sz, const void* pat, size_t plen) {
    auto* m = (const uint8_t*)base; auto* p = (const uint8_t*)pat;
    for (size_t i = 0; i+plen <= sz; ++i)
        if (!memcmp(m+i, p, plen)) return base+i;
    return 0;
}
static bool hookVtable(const char* cls, int slot, void** outOrig, void* hookFn) {
    size_t rsz=0; uintptr_t ro = GlossGetLibSection(MCPE_LIB,".rodata",&rsz);
    if (!ro||!rsz) return false;
    uintptr_t zts = scanMem(ro,rsz,cls,strlen(cls)+1);
    if (!zts) return false;
    size_t dsz=0; uintptr_t drr = GlossGetLibSection(MCPE_LIB,".data.rel.ro",&dsz);
    if (!drr||!dsz) return false;
    uintptr_t zti=0;
    for (size_t i=0;i+sizeof(uintptr_t)<=dsz;i+=sizeof(uintptr_t))
        if (*reinterpret_cast<uintptr_t*>(drr+i)==zts){zti=drr+i-sizeof(uintptr_t);break;}
    if (!zti) return false;
    uintptr_t vtbl=0;
    for (size_t i=0;i+sizeof(uintptr_t)<=dsz;i+=sizeof(uintptr_t))
        if (*reinterpret_cast<uintptr_t*>(drr+i)==zti){vtbl=drr+i+sizeof(uintptr_t);break;}
    if (!vtbl) return false;
    void** vt = reinterpret_cast<void**>(vtbl);
    *outOrig = vt[slot];
    Unprotect(vtbl+slot*sizeof(void*), sizeof(void*));
    vt[slot] = hookFn;
    __builtin___clear_cache((char*)(vtbl+slot*sizeof(void*)),(char*)(vtbl+(slot+1)*sizeof(void*)));
    LOGI("hooked %s slot[%d]", cls, slot);
    return true;
}

static void* g_VanillaCameraAPI_orig = nullptr;
using VanillaCameraAPI_t = int(*)(void*);
static int VanillaCameraAPI_hook(void* self) {
    int v = ((VanillaCameraAPI_t)g_VanillaCameraAPI_orig)(self);
    if (v!=0&&!g_isPatched) PatchNametag();
    if (v==0&&g_isPatched)  UnpatchNametag();
    return v;
}

// ─────────────────────────────────────────────────────────
//  BAGIAN 2: FPS counter
// ─────────────────────────────────────────────────────────

static std::atomic<int> g_fps{0};
static std::atomic<int> g_ping{-1};

static int calcFPS() {
    using namespace std::chrono;
    static auto last = steady_clock::now();
    static int frames=0, cached=0;
    frames++;
    auto now = steady_clock::now();
    auto ms  = duration_cast<milliseconds>(now-last).count();
    if (ms>=1000){cached=(int)(frames*1000.0f/ms);frames=0;last=now;g_fps.store(cached);}
    return g_fps.load();
}

// ─────────────────────────────────────────────────────────
//  BAGIAN 3: Hook getNameTag
//
//  Return type BENAR: std::string const& (dari Actor.h baris 292)
//  using: typedef std::string const& (*getNameTag_t)(void*)
// ─────────────────────────────────────────────────────────

// Return type: const std::string& — sesuai Actor.h
using getNameTag_t = std::string const& (*)(void*);
static void* g_orig_getNameTag = nullptr;

// Buffer per-thread untuk string hasil modifikasi
static thread_local std::string g_modifiedTag;

static std::string const& hook_getNameTag(void* actor) {
    std::string const& original = ((getNameTag_t)g_orig_getNameTag)(actor);

    // Kalau kosong atau terlalu panjang (bukan nama player), return apa adanya
    if (original.empty() || original.size() > 64)
        return original;

    int fps  = calcFPS();
    int ping = g_ping.load();
    char suffix[32];
    if (ping >= 0)
        snprintf(suffix, sizeof(suffix), " (%dms)", ping);
    else
        snprintf(suffix, sizeof(suffix), " (%dfps)", fps);

    g_modifiedTag = original + suffix;
    return g_modifiedTag;
}

static bool hookGetNameTag() {
    // Sig spesifik saja — tidak ada wildcard broad
    static const char* sigs[] = {
        // MCBE 1.20.x - 1.21.x
        "F4 4F BE A9 "
        "FD 7B 01 A9 "
        "FD 43 00 91 "
        "F4 03 00 AA "
        "? ? 40 F9 "
        "? ? 40 F9 "
        "? ? 40 F9 "
        "60 02 40 F9",

        "F4 4F BE A9 "
        "FD 7B 01 A9 "
        "FD 43 00 91 "
        "F4 03 00 AA "
        "? ? 40 F9 "
        "? ? 40 F9 "
        "68 02 40 F9",

        // MCBE 1.19.x
        "F3 0F 1E F8 "
        "FD 7B BF A9 "
        "FD 03 00 91 "
        "F3 03 00 AA "
        "? ? 40 F9 "
        "? ? 40 F9 "
        "? ? 40 F9",

        nullptr
    };

    for (int i = 0; sigs[i]; ++i) {
        uintptr_t addr = pl::signature::pl_resolve_signature(sigs[i], MCPE_LIB);
        if (!addr) { LOGI("getNameTag sig[%d]: not found", i); continue; }

        void* orig = nullptr;
        void* h = GlossHook((void*)addr, (void*)hook_getNameTag, &orig);
        if (h) {
            g_orig_getNameTag = orig;
            LOGI("getNameTag sig[%d] hooked OK", i);
            return true;
        }
        LOGE("getNameTag sig[%d]: GlossHook failed", i);
    }
    LOGE("getNameTag: semua sig tidak match — FPS off, nametag normal");
    return false;
}

// ─────────────────────────────────────────────────────────
//  ENTRY POINT
// ─────────────────────────────────────────────────────────
__attribute__((constructor))
void ThirdPersonNametag_Init() {
    GlossInit(true);
    hookVtable("16VanillaCameraAPI", 7, &g_VanillaCameraAPI_orig, (void*)VanillaCameraAPI_hook);
    if (!g_isPatched) PatchNametag();
    bool ok = hookGetNameTag();
    LOGI("FPSNametag v6 ready! fps=%s", ok?"ON":"OFF");
}

__attribute__((destructor))
void ThirdPersonNametag_Shutdown() {
    if (g_isPatched) UnpatchNametag();
}

#endif
