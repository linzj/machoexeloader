// pldr — ntdll-only pure loader skeleton. No CRT, no shim layer, except two
// targeted IAT hooks working around Bun's console wake race (see below).
//
// Design (validated by ../tlsprobe):
//   - links only against ntdll; kernel32/kernelbase are force-loaded by the OS
//     but stay out of our way (kernelbase holds TLS slot 1 after us)
//   - we carry a graft TLS directory: as the process image we take TLS slot 0
//     at process start; after mapping the target we rewrite our LdrpTlsList
//     entry so slot-0 blocks come from the TARGET's template + callbacks.
//     ntdll then does per-thread TLS natively on every current/future thread.
//   - imports are bound to the real host DLLs (LdrLoadDll/LdrGetProcedureAddress)
//   - PEB is patched (ImageBaseAddress/CommandLine/ImagePathName/LDR names)
//     BEFORE any host DLL can poison kernelbase's GetCommandLine cache
//   - then we jump to the target entry on the main thread.
//
// Build: see build.sh (cl /GS- + link /NODEFAULTLIB /ENTRY:pldr_main ntdll.lib)

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int i32;
typedef unsigned long long u64;
typedef long long i64;
typedef long NTSTATUS;
typedef void *HANDLE;
typedef unsigned short wchar16_t;

#include <intrin.h>

#define NTAPI __stdcall
#define NTSYSAPI __declspec(dllimport)

// ---- graft TLS directory (replaces the CRT's _tls_used) -------------------
typedef struct {
    u64 StartAddressOfRawData;
    u64 EndAddressOfRawData;
    u64 AddressOfIndex;
    u64 AddressOfCallBacks;
    u32 SizeOfZeroFill;
    u32 Characteristics;
} TLS_DIR64;

#define GRAFT_SIZE (4u * 1024u * 1024u) // slot-0 block reservation

// The graft block must be RAW template size, not zero-fill: measured on
// Win11 22621, SizeOfZeroFill is NOT counted when ntdll sizes per-thread
// TLS blocks, so a small template + large zero-fill produces tiny blocks and
// copying the target's template over them smashes the heap. Point the TLS
// directory's template range at a big BSS array instead (all zeros; the
// content is replaced by the target's template at graft time).
static u8 graft_space[GRAFT_SIZE];
u32 _tls_index = 0;
#pragma section(".tls", read, write)
#pragma section(".tls$zzz", read, write)
__declspec(allocate(".tls")) char _tls_start = 0;
__declspec(allocate(".tls$zzz")) char _tls_end = 0;
TLS_DIR64 _tls_used = {
    (u64)graft_space, (u64)graft_space + GRAFT_SIZE, (u64)&_tls_index,
    0, 0, 0,
};

// ---- ntdll imports ---------------------------------------------------------
typedef struct { u16 Length, MaximumLength; wchar16_t *Buffer; } UNICODE_STRING;
typedef struct { u32 Length; HANDLE RootDirectory; UNICODE_STRING *ObjectName; u32 Attributes; void *SD, *SQOS; } OBJECT_ATTRIBUTES;
typedef struct { NTSTATUS Status; u64 Information; } IO_STATUS_BLOCK;
typedef struct { u16 Length, MaximumLength; char *Buffer; } ANSI_STRING;

NTSYSAPI NTSTATUS NTAPI NtCreateFile(HANDLE *, u32, OBJECT_ATTRIBUTES *, IO_STATUS_BLOCK *, i64 *, u32, u32, u32, u32, void *, u32);
NTSYSAPI NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, void *, u32, i64 *, u32 *);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, void **, u64, u64 *, u32, u32);
NTSYSAPI NTSTATUS NTAPI NtQueryInformationFile(HANDLE, IO_STATUS_BLOCK *, void *, u32, u32);
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, void *, u32, i64 *, u32 *);
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
NTSYSAPI void *NTAPI RtlAllocateHeap(void *, u32, u64);
NTSYSAPI u8 NTAPI RtlFreeHeap(void *, u32, void *);
NTSYSAPI void NTAPI RtlInitUnicodeString(UNICODE_STRING *, const wchar16_t *);
NTSYSAPI NTSTATUS NTAPI LdrLoadDll(wchar16_t *, u32 *, UNICODE_STRING *, HANDLE *);
NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddress(HANDLE, ANSI_STRING *, u32, void **);
NTSYSAPI u8 NTAPI RtlAddFunctionTable(void *, u32, u64);

// ---------------------------------------------------------------- utilities

static void *memcpy(void *d, const void *s, u64 n) {
    u8 *dd = (u8 *)d;
    const u8 *ss = (const u8 *)s;
    while (n--) *dd++ = *ss++;
    return d;
}
static void *memset(void *d, int c, u64 n) {
    u8 *dd = (u8 *)d;
    while (n--) *dd++ = (u8)c;
    return d;
}
static u64 cstrlen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static u64 wcslen16(const wchar16_t *s) { u64 n = 0; while (s[n]) n++; return n; }

static u64 teb(void) { return __readgsqword(0x30); }
static u64 peb(void) { return *(u64 *)(teb() + 0x60); }
static u64 peb_pp(void) { return *(u64 *)(peb() + 0x20); }
static HANDLE std_out(void) { return *(HANDLE *)(peb_pp() + 0x28); }
static void *process_heap(void) { return *(void **)(peb() + 0x30); }

static void raw(const char *s) {
    IO_STATUS_BLOCK iosb;
    NtWriteFile(std_out(), 0, 0, 0, &iosb, (void *)s, (u32)cstrlen(s), 0, 0);
}
// Diagnostics are silent by default (would pollute the target's stdout/TUI); PLDR_DEBUG=1 enables
static int g_debug = 0;
static void say(const char *s) { if (g_debug) raw(s); }
static void say_hex(u64 v) {
    char b[17];
    for (int i = 15; i >= 0; i--) b[i] = "0123456789abcdef"[(v >> ((15 - i) * 4)) & 0xF];
    b[16] = 0;
    say("0x");
    say(b);
}
static void kv(const char *k, u64 v) { say(k); say_hex(v); say("\n"); }
static void as_init(ANSI_STRING *a, char *s) {
    u32 l = 0;
    while (s[l]) l++;
    a->Length = (u16)l;
    a->MaximumLength = (u16)(l + 1);
    a->Buffer = s;
}
static void die(const char *msg, u32 code) {
    raw("pldr: FAIL: ");
    raw(msg);
    raw("\n");
    NtTerminateProcess((HANDLE)-1, code);
}

// Value of "name=" in the PEB environment block (RTL_USER_PROCESS_PARAMETERS.Environment +0x80), 0 if absent
static const wchar16_t *env_val(const wchar16_t *env, const char *name) {
    while (env && *env) {
        u64 i = 0;
        while (name[i] && env[i] == (wchar16_t)name[i]) i++;
        if (!name[i] && env[i] == L'=') return env + i + 1;
        while (*env) env++;
        env++;
    }
    return 0;
}

static int env_has(const wchar16_t *env, const char *name) {
    return env_val(env, name) != 0;
}

// ------------------------------------------------------------- LDR helpers
#define LDR_INLOAD 0x00
#define LDR_DLLBASE 0x30
#define LDR_FULLDLLNAME 0x48
#define LDR_BASEDLLNAME 0x58

static u64 ldr_first_entry(void) {
    u64 head = *(u64 *)(peb() + 0x18) + 0x10;
    return *(u64 *)head; // first entry = the process image (us)
}

static u64 find_ntdll(void) {
    u64 head = *(u64 *)(peb() + 0x18) + 0x10;
    for (u64 e = *(u64 *)head; e != head; e = *(u64 *)(e + LDR_INLOAD)) {
        wchar16_t *buf = *(wchar16_t **)(e + LDR_BASEDLLNAME + 8);
        const char *want = "ntdll.dll";
        if (!buf) continue;
        u64 i = 0;
        for (;; i++) {
            char a = want[i], b = (char)(buf[i] & 0xFF);
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
            if (!a) return *(u64 *)(e + LDR_DLLBASE);
        }
    }
    return 0;
}

// ------------------------------------------- ntdll internals (signatures)

// Win11 22621 ntdll!LdrpHandleTlsData prologue + security-cookie reference.
static const u8 SIG[] = {0x4c, 0x8b, 0xdc, 0x49, 0x89, 0x5b, 0x10, 0x49,
                         0x89, 0x73, 0x18, 0x57, 0x41, 0x54, 0x41, 0x55,
                         0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xec, 0x00,
                         0x01, 0x00, 0x00};
static const u8 SIG2[] = {0x48, 0x8b, 0x05, 0, 0, 0, 0, 0x48, 0x33, 0xc4,
                          0x48, 0x89, 0x84, 0x24, 0xf0, 0x00, 0x00, 0x00,
                          0x48, 0x8b, 0xf9};
static const u8 SIG2_MASK[] = {1, 1, 1, 0, 0, 0, 0, 1, 1, 1,
                               1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

static u64 scan_text(u64 base, const u8 *sig, u32 siglen, const u8 *sig2, const u8 *mask, u32 sig2len) {
    u64 nt = base + *(u32 *)(base + 0x3C);
    u64 opt = nt + 24;
    u16 nsec = *(u16 *)(nt + 6);
    u64 secs = opt + *(u16 *)(nt + 20);
    for (u16 i = 0; i < nsec; i++) {
        u64 s = secs + i * 40;
        const u8 *nm = (const u8 *)s;
        if (!(nm[0] == '.' && nm[1] == 't' && nm[2] == 'e')) continue;
        u32 vs = *(u32 *)(s + 8);
        u64 va = base + *(u32 *)(s + 12);
        for (u64 o = 0; o + siglen + sig2len < vs; o++) {
            const u8 *p = (const u8 *)(va + o);
            u64 j = 0;
            for (; j < siglen; j++)
                if (p[j] != sig[j]) break;
            if (j < siglen) continue;
            const u8 *q = p + siglen;
            for (j = 0; j < sig2len; j++)
                if (mask[j] && q[j] != sig2[j]) break;
            if (j == sig2len) return (u64)p;
        }
    }
    return 0;
}

// Follow the call from LdrpHandleTlsData to LdrpAllocateTlsEntry (matched by
// prologue), then decode its first `lea rcx,[rip+x]` -> LdrpTlsList.
static u64 find_ldrp_tls_list(u64 fn) {
    static const u8 PROL[] = {0x4c, 0x89, 0x4c, 0x24, 0x20, 0x4c, 0x89, 0x44,
                              0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x53,
                              0x56, 0x57};
    for (u64 o = 0; o < 0x600; o++) {
        const u8 *p = (const u8 *)(fn + o);
        if (*p != 0xE8) continue;
        u64 callee = (u64)(p + 5) + (i64)(*(i32 *)(p + 1));
        u64 j = 0;
        for (; j < sizeof(PROL); j++)
            if (*(const u8 *)(callee + j) != PROL[j]) break;
        if (j < sizeof(PROL)) continue;
        for (u64 q = 0; q < 0x180; q++) {
            const u8 *r = (const u8 *)(callee + q);
            if (r[0] == 0x48 && r[1] == 0x8D && r[2] == 0x0D)
                return (u64)(r + 7) + (i64)(*(i32 *)(r + 3));
        }
    }
    return 0;
}

// ------------------------------------------------------------- PE mapping

static u64 g_target = 0;

static u64 map_image(const wchar16_t *ntpath, u32 *entry_rva_out, u32 *tls_rva_out) {
    UNICODE_STRING us;
    us.Buffer = (wchar16_t *)ntpath;
    u32 n = 0;
    while (ntpath[n]) n++;
    us.Length = (u16)(n * 2);
    us.MaximumLength = us.Length + 2;
    OBJECT_ATTRIBUTES oa;
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.ObjectName = &us;
    IO_STATUS_BLOCK iosb;
    HANDLE f = 0;
    NTSTATUS st = NtCreateFile(&f, 0x80000000 | 0x100000, &oa, &iosb, 0, 0x80, 1, 1, 0x20 | 0x40, 0, 0);
    if (st < 0) die("open target", 2);
    u8 fsi[24];
    st = NtQueryInformationFile(f, &iosb, fsi, sizeof(fsi), 5);
    if (st < 0) die("query size", 3);
    u64 filesz = *(u64 *)(fsi + 8);
    u8 *file = (u8 *)RtlAllocateHeap(process_heap(), 0, filesz);
    if (!file) die("alloc file buf", 4);
    i64 off = 0;
    st = NtReadFile(f, 0, 0, 0, &iosb, file, (u32)filesz, &off, 0);
    NtClose(f);
    if (st < 0) die("read target", 5);

    u64 nt = *(u32 *)(file + 0x3C);
    u64 opt = nt + 24;
    if (*(u16 *)(file + opt) != 0x020B) die("not PE32+", 6);
    u64 image_base = *(u64 *)(file + opt + 24);
    u32 size_of_image = *(u32 *)(file + opt + 56);
    u32 size_of_headers = *(u32 *)(file + opt + 60);
    *entry_rva_out = *(u32 *)(file + opt + 16);
    *tls_rva_out = *(u32 *)(file + opt + 112 + 9 * 8);
    u32 reloc_rva = *(u32 *)(file + opt + 112 + 5 * 8);
    u16 nsec = *(u16 *)(file + nt + 6);
    u64 secs = (u64)file + nt + 24 + *(u16 *)(file + nt + 20);

    void *base = (void *)image_base;
    u64 region = size_of_image;
    st = NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &region, 0x3000, 0x40);
    if (st < 0 || base != (void *)image_base) {
        base = 0;
        region = size_of_image;
        st = NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &region, 0x3000, 0x40);
        if (st < 0) die("alloc image", 7);
    }
    u64 b = (u64)base;
    i64 delta = (i64)(b - image_base);
    memcpy(base, file, size_of_headers < filesz ? size_of_headers : filesz);
    for (u16 i = 0; i < nsec; i++) {
        u64 s = secs + i * 40;
        u32 va = *(u32 *)(s + 12), rs = *(u32 *)(s + 16), ro = *(u32 *)(s + 20);
        if (rs) memcpy((u8 *)b + va, file + ro, rs);
    }
    if (delta && reloc_rva) {
        u64 p = b + reloc_rva;
        for (;;) {
            u32 prva = *(u32 *)p, bsz = *(u32 *)(p + 4);
            if (!prva || bsz < 8) break;
            for (u32 j = 8; j + 2 <= bsz; j += 2) {
                u16 e = *(u16 *)(p + j);
                u64 a = b + prva + (e & 0xFFF);
                if ((e >> 12) == 10) *(u64 *)a += (u64)delta;
                else if ((e >> 12) == 3) *(u32 *)a += (u32)delta;
            }
            p += bsz;
        }
    }
    RtlFreeHeap(process_heap(), 0, file);
    kv("mapped at ", b);
    if (delta) kv("delta ", (u64)delta);
    return b;
}

// -------------------------------------------------- console wake race fix
//
// Bun's own terminal-detection writes make the console-input arming wait
// fire; if the resulting wake packet is dequeued while the console driver
// sits in its reset window, the pending read takes the wrong (line-mode)
// branch and interactive input dies. Observed via cdb on the frozen TUI:
// main thread idle in GetQueuedCompletionStatusEx, zero threads in
// ReadConsoleInputW. Same fix peldr's shim had: delay the console wake
// packet so the reset finishes first. PLDR_WAKE_DELAY_MS overrides the
// delay, 0 disables.
//
// ------------------------------------------------- pool callback trampoline
//
// ntdll!RtlQueueWorkItem drops work items whose callback address does not
// belong to a registered module (RtlPcToFileHeader fails -> item freed,
// caller still gets success). Bun queues its console read dispatcher this
// way, and RtlAddFunctionTable does NOT feed that lookup -- so target
// callbacks must be entered via a trampoline inside OUR (properly
// registered) image. Pool threads get the target's TLS natively via the
// graft, so the trampoline needs no TLS work, unlike peldr's shim.

typedef int BOOL;
typedef BOOL(NTAPI *RegisterWait_t)(HANDLE *, HANDLE, void *, void *, u32, u32);
typedef BOOL(NTAPI *PostQueued_t)(HANDLE, u32, u64, void *);
typedef BOOL(NTAPI *QueueWork_t)(void *, void *, u32);
typedef u32(NTAPI *GetFileType_t)(HANDLE);
typedef void(NTAPI *Sleep_t)(u32);

static RegisterWait_t real_RegisterWait;
static PostQueued_t real_PostQueued;
static QueueWork_t real_QueueWork;
static GetFileType_t pGetFileType;
static Sleep_t pSleep;
static u64 g_con_wait_ctx;      // Context of the console-input wait registration
static u32 g_wake_delay_ms = 20;

static int cstreq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static void ensure_k32(void) {
    if (pSleep) return;
    const char *name = "kernel32.dll";
    wchar16_t wn[32];
    u32 i = 0;
    for (; name[i]; i++) wn[i] = (wchar16_t)(u8)name[i];
    wn[i] = 0;
    UNICODE_STRING dn;
    RtlInitUnicodeString(&dn, wn);
    HANDLE mod = 0;
    if (LdrLoadDll(0, 0, &dn, &mod) < 0 || !mod) return;
    ANSI_STRING as;
    void *fn = 0;
    as_init(&as, "GetFileType");
    if (LdrGetProcedureAddress(mod, &as, 0, &fn) >= 0) pGetFileType = (GetFileType_t)fn;
    fn = 0;
    as_init(&as, "Sleep");
    if (LdrGetProcedureAddress(mod, &as, 0, &fn) >= 0) pSleep = (Sleep_t)fn;
}

static BOOL NTAPI hook_RegisterWait(HANDLE *new_wait, HANDLE object, void *cb, void *ctx, u32 ms, u32 flags) {
    BOOL rc = real_RegisterWait(new_wait, object, cb, ctx, ms, flags);
    if (pGetFileType && pGetFileType(object) == 2) // FILE_TYPE_CHAR: console input
        g_con_wait_ctx = (u64)ctx;
    return rc;
}

// WorkPack carries the real (cb, ctx) through the pool; the trampoline lives
// in pldr's registered image so RtlQueueWorkItem's module pin succeeds.
typedef struct { u64 cb; u64 ctx; } WorkPack;

static u32 NTAPI pool_trampoline(void *p) {
    WorkPack w = *(WorkPack *)p;
    RtlFreeHeap(process_heap(), 0, p);
    return ((u32(NTAPI *)(void *))w.cb)((void *)w.ctx);
}

static BOOL NTAPI hook_QueueWork(void *cb, void *ctx, u32 flags) {
    WorkPack *w = (WorkPack *)RtlAllocateHeap(process_heap(), 0, sizeof(WorkPack));
    if (!w) return 0;
    w->cb = (u64)cb;
    w->ctx = (u64)ctx;
    if (real_QueueWork(pool_trampoline, w, flags)) return 1;
    RtlFreeHeap(process_heap(), 0, w);
    return 0;
}

static BOOL NTAPI hook_PostQueued(HANDLE port, u32 bytes, u64 key, void *overlapped) {
    u64 ctx = g_con_wait_ctx;
    // The wake packet's OVERLAPPED lives inside the registration context
    // object (observed at ctx+0xB0 on claude 2.1.276; peldr's shim hardcoded
    // ctx+0x40 which went stale). Match a range to tolerate layout drift.
    if (ctx && (u64)overlapped - ctx < 0x100 && g_wake_delay_ms && pSleep)
        pSleep(g_wake_delay_ms);
    return real_PostQueued(port, bytes, key, overlapped);
}

// --------------------------------------------------------- import binding

static int bind_imports(u64 base) {
    u64 nt = base + *(u32 *)(base + 0x3C);
    u64 opt = nt + 24;
    u32 ir = *(u32 *)(opt + 112 + 1 * 8);
    if (!ir) return 1;
    u64 d = base + ir;
    for (; *(u32 *)(d + 12); d += 20) {
        u32 oft = *(u32 *)d, ft = *(u32 *)(d + 16);
        const char *dll = (const char *)(base + *(u32 *)(d + 12));
        wchar16_t wn[64];
        u32 i = 0;
        for (; dll[i] && i < 60; i++) wn[i] = (wchar16_t)(u8)dll[i];
        wn[i] = 0;
        UNICODE_STRING dn;
        RtlInitUnicodeString(&dn, wn);
        HANDLE mod = 0;
        NTSTATUS st = LdrLoadDll(0, 0, &dn, &mod);
        if (st < 0) {
            say("LdrLoadDll failed: ");
            say(dll);
            say("\n");
            return 0;
        }
        u64 ilt = base + (oft ? oft : ft);
        for (u32 k = 0;; k++) {
            u64 e = *(u64 *)(ilt + k * 8);
            if (!e) break;
            void *fn = 0;
            char *nm = 0;
            if (e & 0x8000000000000000ULL) {
                st = LdrGetProcedureAddress(mod, 0, (u32)(e & 0xFFFF), &fn);
            } else {
                nm = (char *)(base + (u32)e) + 2;
                ANSI_STRING as;
                u32 l = 0;
                while (nm[l]) l++;
                as.Length = (u16)l;
                as.MaximumLength = (u16)(l + 1);
                as.Buffer = nm;
                st = LdrGetProcedureAddress(mod, &as, 0, &fn);
            }
            if (st < 0 || !fn) {
                say("import resolve failed: ");
                say(dll);
                say("\n");
                return 0;
            }
            if (nm && cstreq(nm, "RegisterWaitForSingleObject")) {
                ensure_k32();
                real_RegisterWait = (RegisterWait_t)fn;
                fn = hook_RegisterWait;
                say("hook: RegisterWaitForSingleObject\n");
            } else if (nm && cstreq(nm, "PostQueuedCompletionStatus")) {
                ensure_k32();
                real_PostQueued = (PostQueued_t)fn;
                fn = hook_PostQueued;
                say("hook: PostQueuedCompletionStatus\n");
            } else if (nm && cstreq(nm, "QueueUserWorkItem")) {
                real_QueueWork = (QueueWork_t)fn;
                fn = hook_QueueWork;
                say("hook: QueueUserWorkItem\n");
            }
            *(u64 *)(base + ft + k * 8) = (u64)fn;
        }
    }
    return 1;
}

// -------------------------------------------------------------- TLS graft

typedef NTSTATUS(NTAPI *LdrpHandleTlsData_t)(void *entry);

static void graft_tls(u64 base, u32 tls_rva) {
    if (!tls_rva) return;
    u64 ntdll = find_ntdll();
    if (!ntdll) die("ntdll base", 8);
    u64 fn = scan_text(ntdll, SIG, sizeof(SIG), SIG2, SIG2_MASK, sizeof(SIG2));
    if (!fn) die("LdrpHandleTlsData not found", 9);
    u64 tlsp = find_ldrp_tls_list(fn);
    if (!tlsp) die("LdrpTlsList not found", 10);
    u64 our = 0;
    for (u64 e = *(u64 *)tlsp; e && e != tlsp; e = *(u64 *)e) {
        if (*(u64 *)(e + 0x20) == (u64)&_tls_index) {
            our = e;
            break;
        }
    }
    if (!our) die("own TLS entry not found", 11);
    u64 tlsdir = base + tls_rva;
    u64 tstart = *(u64 *)(tlsdir + 0);
    u64 tend = *(u64 *)(tlsdir + 8);
    u64 tindex = *(u64 *)(tlsdir + 16);
    u64 tcbs = *(u64 *)(tlsdir + 24);
    u32 tzf = *(u32 *)(tlsdir + 32);
    *(u64 *)(our + 0x10) = tstart;
    *(u64 *)(our + 0x18) = tend;
    *(u64 *)(our + 0x28) = tcbs;
    *(u32 *)(our + 0x30) = tzf;
    _tls_used.AddressOfCallBacks = tcbs;
    if (tindex) *(u32 *)tindex = 0;
    // this thread's slot-0 block content (allocated at process start from
    // our zero graft template)
    u64 arr = __readgsqword(0x58);
    memcpy((void *)(*(u64 *)arr), (void *)tstart, (u32)(tend - tstart));
    // process-attach semantics: run the target's TLS callbacks once ourselves
    if (tcbs) {
        for (u32 i = 0;; i++) {
            u64 f = *(u64 *)(tcbs + i * 8);
            if (!f || i > 128) break;
            ((void(NTAPI *)(u64, u32, u64))f)(base, 1, 0);
        }
    }
    say("TLS grafted onto slot 0\n");
}

// kernelbase snapshots the command line at process init into its own
// BaseUnicodeCommandLine / BaseAnsiCommandLine globals (a UNICODE_STRING;
// GetCommandLineW/A just return its .Buffer). No-CRT startup means nobody
// touched them yet — but PEB patching alone does NOT reach them. Find the
// globals by decoding the exported functions' first instruction:
//   GetCommandLineW: 48 8b 05 <rel32> c3   (mov rax,[rip+x]; ret)
static void patch_cmdline_cache(const wchar16_t *wide, const char *ansi) {
    UNICODE_STRING kb;
    RtlInitUnicodeString(&kb, L"kernelbase.dll");
    HANDLE kbh = 0;
    if (LdrLoadDll(0, 0, &kb, &kbh) < 0) die("kernelbase", 20);
    const char *names[2] = {"GetCommandLineW", "GetCommandLineA"};
    u64 vals[2];
    vals[0] = (u64)wide;
    vals[1] = (u64)ansi;
    for (int i = 0; i < 2; i++) {
        ANSI_STRING an;
        as_init(&an, (char *)names[i]);
        void *fn = 0;
        if (LdrGetProcedureAddress(kbh, &an, 0, &fn) < 0 || !fn) die("GetCommandLine resolve", 21);
        u8 *p = (u8 *)fn;
        if (!(p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x05)) die("GetCommandLine shape changed", 22);
        u64 buf_field = (u64)(p + 7) + (i64)(*(i32 *)(p + 3)); // &global.Buffer
        u64 len = i == 0 ? wcslen16(wide) * 2 : cstrlen(ansi);
        *(u16 *)(buf_field - 8) = (u16)len;         // UNICODE_STRING.Length
        *(u16 *)(buf_field - 6) = (u16)(len + 2);   // MaximumLength (bytes, NUL incl.)
        *(u64 *)buf_field = vals[i];                // UNICODE_STRING.Buffer
    }
    say("cmdline cache patched\n");
}

// ------------------------------------------------------------ PEB patching

static void patch_peb(u64 base, const wchar16_t *cmdline, const wchar16_t *path) {
    static wchar16_t cmdbuf[32768];
    u64 cl = wcslen16(cmdline);
    memcpy(cmdbuf, cmdline, (cl + 1) * 2);
    u64 pp = peb_pp();
    // ProcessParameters.CommandLine (+0x70)
    *(u16 *)(pp + 0x70) = (u16)(cl * 2);
    *(u16 *)(pp + 0x72) = (u16)(cl * 2 + 2);
    *(u64 *)(pp + 0x78) = (u64)cmdbuf;
    // ProcessParameters.ImagePathName (+0x60)
    u64 pl = wcslen16(path);
    static wchar16_t pathbuf[1024];
    memcpy(pathbuf, path, (pl + 1) * 2);
    *(u16 *)(pp + 0x60) = (u16)(pl * 2);
    *(u16 *)(pp + 0x62) = (u16)(pl * 2 + 2);
    *(u64 *)(pp + 0x68) = (u64)pathbuf;
    // PEB.ImageBaseAddress (+0x10)
    *(u64 *)(peb() + 0x10) = base;
    // LDR entry names (first entry = process image)
    u64 e = ldr_first_entry();
    *(u16 *)(e + LDR_FULLDLLNAME) = (u16)(pl * 2);
    *(u16 *)(e + LDR_FULLDLLNAME + 2) = (u16)(pl * 2 + 2);
    *(u64 *)(e + LDR_FULLDLLNAME + 8) = (u64)pathbuf;
    // base name = after last backslash
    u64 bs = 0;
    for (u64 i = 0; i < pl; i++)
        if (path[i] == L'\\') bs = i + 1;
    *(u16 *)(e + LDR_BASEDLLNAME) = (u16)((pl - bs) * 2);
    *(u16 *)(e + LDR_BASEDLLNAME + 2) = (u16)((pl - bs) * 2 + 2);
    *(u64 *)(e + LDR_BASEDLLNAME + 8) = (u64)(pathbuf + bs);
    say("PEB patched\n");
}

// ------------------------------------------------------------------- main

void pldr_main(void) {
    const wchar16_t *env = *(const wchar16_t **)(peb_pp() + 0x80);
    g_debug = env_has(env, "PLDR_DEBUG");
    const wchar16_t *wd = env_val(env, "PLDR_WAKE_DELAY_MS");
    if (wd) {
        u32 v = 0;
        while (*wd >= L'0' && *wd <= L'9') { v = v * 10 + (u32)(*wd - L'0'); wd++; }
        g_wake_delay_ms = v;
    }
    say("pldr: start\n");

    // Own command line -> strip our argv[0]; the rest is the target's.
    u64 pp = peb_pp();
    u16 clen = *(u16 *)(pp + 0x70);
    wchar16_t *cmd = *(wchar16_t **)(pp + 0x78);
    u32 i = 0, n = clen / 2;
    while (i < n && (cmd[i] == L' ' || cmd[i] == L'\t')) i++;
    if (i < n && cmd[i] == L'"') {
        i++;
        while (i < n && cmd[i] != L'"') i++;
        if (i < n) i++;
    } else {
        while (i < n && cmd[i] != L' ' && cmd[i] != L'\t') i++;
    }
    while (i < n && (cmd[i] == L' ' || cmd[i] == L'\t')) i++;
    if (i >= n) die("usage: pldr.exe <target.exe> [args...]", 1);
    wchar16_t *rest = cmd + i;
    u32 restlen = n - i;

    // target path = first token of rest (unquoted)
    static wchar16_t tpath[1024];
    u32 tp = 0;
    u32 j = 0;
    int quoted = 0;
    if (rest[j] == L'"') { quoted = 1; j++; }
    while (j < restlen) {
        wchar16_t c = rest[j];
        if (quoted ? (c == L'"') : (c == L' ' || c == L'\t')) break;
        tpath[tp++] = c;
        j++;
    }
    tpath[tp] = 0;

    // NT path: absolute if it has a drive letter, else cwd-relative
    static wchar16_t ntpath[1200];
    u32 k = 0;
    const wchar16_t *pfx = L"\\??\\";
    for (u32 q = 0; pfx[q]; q++) ntpath[k++] = pfx[q];
    if (!(tp > 2 && tpath[1] == L':')) {
        u16 cwdlen = *(u16 *)(pp + 0x38);
        wchar16_t *cwd = *(wchar16_t **)(pp + 0x38 + 8);
        for (u32 q = 0; q < cwdlen / 2; q++) ntpath[k++] = cwd[q];
        if (k && ntpath[k - 1] != L'\\') ntpath[k++] = L'\\';
    }
    for (u32 q = 0; q < tp; q++) ntpath[k++] = tpath[q];
    ntpath[k] = 0;

    u32 entry_rva, tls_rva;
    u64 base = map_image(ntpath, &entry_rva, &tls_rva);
    g_target = base;

    // NUL-terminated fake command line for the target
    static wchar16_t fakew[32768];
    if (restlen > 32760) restlen = 32760;
    memcpy(fakew, rest, restlen * 2);
    fakew[restlen] = 0;
    static char fakea[32768];
    for (u32 q = 0; q < restlen; q++) fakea[q] = (char)(rest[q] & 0x7F);
    fakea[restlen] = 0;

    // PEB patch + kernelbase cmdline cache patch BEFORE host-DLL inits run.
    if (!env_has(env, "PLDR_NO_PEB")) patch_peb(base, fakew, tpath);
    if (!env_has(env, "PLDR_NO_CMDCACHE")) patch_cmdline_cache(fakew, fakea);

    if (!bind_imports(base)) die("bind imports", 12);
    say("imports bound\n");

    // .pdata registration for SEH/unwind.
    u64 nt = base + *(u32 *)(base + 0x3C);
    u32 pd_rva = *(u32 *)(nt + 24 + 112 + 3 * 8);
    u32 pd_sz = *(u32 *)(nt + 24 + 112 + 3 * 8 + 4);
    if (pd_rva && !env_has(env, "PLDR_NO_PDATA")) RtlAddFunctionTable((void *)(base + pd_rva), pd_sz / 12, base);
    say("pdata registered\n");

    say("grafting TLS...\n");
    if (!env_has(env, "PLDR_NO_GRAFT")) graft_tls(base, tls_rva);

    say("pldr: jumping to entry\n");
    int rc = ((int(NTAPI *)(void))(base + entry_rva))();
    NtTerminateProcess((HANDLE)-1, rc);
}
