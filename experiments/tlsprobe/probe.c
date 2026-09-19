// ntdll-only probe: hand-map a TLS-bearing DLL and register it with the
// undocumented ntdll!LdrpHandleTlsData, then verify that ntdll natively does
// everything peldr's shim/tls machinery currently fakes:
//   1. an ntdll-only process starts with zero TLS slots taken
//   2. registration assigns the target slot 0 (Bun-style hardcoded slot 0)
//   3. the current thread's TLS array is retrofitted; new threads get the
//      target's block natively (no thread-creation interception)
//   4. a later LdrLoadDll of a TLS-bearing host DLL (kernelbase) integrates
//      natively and takes slot 1
//   5. thread exit teardown is native (heap survives)
//
// Build: /NODEFAULTLIB /ENTRY:probe_main, imports only from ntdll.
// No CRT: no stdio, no strings — raw NtWriteFile to the PEB stdout handle.

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int i32;
typedef unsigned long long u64;
typedef long long i64;
typedef long NTSTATUS;
typedef void *HANDLE;
typedef unsigned short wchar16_t; // avoid CRT wchar_t dependence

#include <intrin.h> // compiler intrinsics only (__readgsqword), no CRT

// ---- graft TLS directory (replaces the CRT's _tls_used) -------------------
// The probe deliberately carries a TLS directory: as the process image it is
// first in load order, so it takes slot 0 (before kernelbase). At graft time
// we rewrite our TLS entry in ntdll's LdrpTlsList so slot 0's per-thread
// blocks get the TARGET's template and callbacks, natively.
typedef struct {
    u64 StartAddressOfRawData;
    u64 EndAddressOfRawData;
    u64 AddressOfIndex;
    u64 AddressOfCallBacks;
    u32 SizeOfZeroFill;
    u32 Characteristics;
} TLS_DIR64;

#define GRAFT_ZERO_FILL (256u * 1024u) // room for any target's TLS block

#pragma section(".tls", read, write)
#pragma section(".tls$zzz", read, write)
__declspec(allocate(".tls")) char _tls_start = 0;
__declspec(allocate(".tls$zzz")) char _tls_end = 0;
u32 _tls_index = 0;
TLS_DIR64 _tls_used = {
    (u64)&_tls_start,
    (u64)&_tls_end,
    (u64)&_tls_index,
    0,               // AddressOfCallBacks (grafted to the target's)
    GRAFT_ZERO_FILL, // block size = 1-byte template + this zero-fill
    0,
};

#define NTAPI __stdcall
#define NTSYSAPI __declspec(dllimport)

typedef struct {
    u16 Length;
    u16 MaximumLength;
    wchar16_t *Buffer;
} UNICODE_STRING;

typedef struct {
    u32 Length;
    HANDLE RootDirectory;
    UNICODE_STRING *ObjectName;
    u32 Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct {
    NTSTATUS Status;
    u64 Information;
} IO_STATUS_BLOCK;

typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct {
    u16 Length;
    u16 MaximumLength;
    char *Buffer;
} ANSI_STRING;

NTSYSAPI NTSTATUS NTAPI NtCreateFile(HANDLE *, u32, OBJECT_ATTRIBUTES *, IO_STATUS_BLOCK *, i64 *, u32, u32, u32, u32, void *, u32);
NTSYSAPI NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, void *, u32, i64 *, u32 *);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, void **, u64, u64 *, u32, u32);
NTSYSAPI NTSTATUS NTAPI NtQueryInformationFile(HANDLE, IO_STATUS_BLOCK *, void *, u32, u32);
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, void *, u32, i64 *, u32 *);
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, u8, i64 *);
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
NTSYSAPI void *NTAPI RtlAllocateHeap(void *, u32, u64);
NTSYSAPI u8 NTAPI RtlFreeHeap(void *, u32, void *);
NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(HANDLE, void *, u8, u32, u64, u64, void *, void *, HANDLE *, CLIENT_ID *);
NTSYSAPI void NTAPI RtlExitUserThread(NTSTATUS);
NTSYSAPI NTSTATUS NTAPI LdrLoadDll(wchar16_t *, u32 *, UNICODE_STRING *, HANDLE *);
NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddress(HANDLE, ANSI_STRING *, u32, void **);
NTSYSAPI void NTAPI RtlInitUnicodeString(UNICODE_STRING *, const wchar16_t *);

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

static u64 cstrlen(const char *s) {
    u64 n = 0;
    while (s[n]) n++;
    return n;
}

static u64 peb(void) { return *(u64 *)(__readgsqword(0x30) + 0x60); }
static u64 peb_pp(void) { return *(u64 *)(peb() + 0x20); }
static HANDLE std_out(void) { return *(HANDLE *)(peb_pp() + 0x28); }
static void *process_heap(void) { return *(void **)(peb() + 0x30); }

static void print(const char *s) {
    IO_STATUS_BLOCK iosb;
    NtWriteFile(std_out(), 0, 0, 0, &iosb, (void *)s, (u32)cstrlen(s), 0, 0);
}

static void print_hex(u64 v) {
    char buf[17];
    for (int i = 15; i >= 0; i--) {
        buf[i] = "0123456789abcdef"[(v >> ((15 - i) * 4)) & 0xF];
    }
    buf[16] = 0;
    print("0x");
    print(buf);
}

static void print_dec(u64 v) {
    char buf[24];
    int i = 23;
    buf[i] = 0;
    if (v == 0) {
        print("0");
        return;
    }
    while (v) {
        buf[--i] = (char)('0' + v % 10);
        v /= 10;
    }
    print(buf + i);
}

static void kv(const char *k, u64 v) {
    print(k);
    print_hex(v);
    print("\n");
}

static int str_eq_ascii_wide(const char *a, const wchar16_t *w) {
    // case-insensitive ascii vs wide compare
    u64 i = 0;
    for (;; i++) {
        char ca = a[i];
        char cw = (char)(w[i] & 0xFF);
        if (cw >= 'A' && cw <= 'Z') cw += 32;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (ca != cw) return 0;
        if (ca == 0) return 1;
    }
}

// --------------------------------------------------------------- LDR walk

// LDR_DATA_TABLE_ENTRY offsets (x64): links +0x00, DllBase +0x30,
// SizeOfImage +0x40, BaseDllName +0x58, TlsIndex +0x6E.
#define LDR_INLOAD 0x00
#define LDR_DLLBASE 0x30
#define LDR_SIZEOFIMAGE 0x40
#define LDR_BASEDLLNAME 0x58
#define LDR_TLSINDEX 0x6E

static u64 ldr_head(void) { return *(u64 *)(peb() + 0x18) + 0x10; }

static int image_has_tls(u64 base) {
    if (*(u16 *)base != 0x5A4D) return 0;
    u64 nt = base + *(u32 *)(base + 0x3C);
    u64 opt = nt + 24;
    if (*(u16 *)opt != 0x020B) return 0;
    return *(u32 *)(opt + 112 + 9 * 8) != 0;
}

static int count_host_tls(void) {
    int n = 0;
    u64 head = ldr_head();
    for (u64 e = *(u64 *)head; e != head; e = *(u64 *)(e + LDR_INLOAD)) {
        if (image_has_tls(*(u64 *)(e + LDR_DLLBASE))) n++;
    }
    return n;
}

static u64 find_module(const char *name) {
    u64 head = ldr_head();
    for (u64 e = *(u64 *)head; e != head; e = *(u64 *)(e + LDR_INLOAD)) {
        u16 len = *(u16 *)(e + LDR_BASEDLLNAME);
        wchar16_t *buf = *(wchar16_t **)(e + LDR_BASEDLLNAME + 8);
        if (buf && str_eq_ascii_wide(name, buf)) {
            (void)len;
            return e; // entry address
        }
    }
    return 0;
}

static void list_modules(void) {
    u64 head = ldr_head();
    for (u64 e = *(u64 *)head; e != head; e = *(u64 *)(e + LDR_INLOAD)) {
        wchar16_t *buf = *(wchar16_t **)(e + LDR_BASEDLLNAME + 8);
        char name[64];
        int i = 0;
        if (buf) {
            for (; i < 60 && buf[i]; i++) name[i] = (char)(buf[i] & 0x7F);
        }
        name[i] = 0;
        print("  module: ");
        print(name);
        print(" base=");
        print_hex(*(u64 *)(e + LDR_DLLBASE));
        print(" tls_dir=");
        print_dec(image_has_tls(*(u64 *)(e + LDR_DLLBASE)));
        print(" tls_index(entry)=");
        print_dec(*(u16 *)(e + LDR_TLSINDEX));
        print("\n");
    }
}

// ------------------------------------------------------------ PE mapping

static u64 g_target = 0;
static u32 g_target_size = 0;
static u32 g_tls_rva = 0;

static u64 rva2va(u64 rva) { return g_target + rva; }

static int map_target(const wchar16_t *ntpath) {
    UNICODE_STRING us;
    us.Length = 0;
    us.MaximumLength = 0;
    us.Buffer = (wchar16_t *)ntpath;
    while (ntpath[us.Length]) us.Length++;
    us.Length *= 2;
    us.MaximumLength = us.Length + 2;

    OBJECT_ATTRIBUTES oa;
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.ObjectName = &us;

    IO_STATUS_BLOCK iosb;
    HANDLE f = 0;
    NTSTATUS st = NtCreateFile(&f, 0x80000000 | 0x20000000 | 0x100000 /*GENERIC_READ|GENERIC_EXECUTE|SYNCHRONIZE*/, &oa, &iosb,
                               0, 0x80 /*FILE_ATTRIBUTE_NORMAL*/, 1 /*FILE_SHARE_READ*/,
                               1 /*FILE_OPEN*/, 0x20 | 0x40 /*SYNCHRONOUS_IO_NONALERT|NON_DIRECTORY_FILE*/, 0, 0);
    if (st < 0) {
        kv("NtCreateFile failed: ", (u32)st);
        return 0;
    }
    // Whole file into a heap buffer.
    u8 fsi[24]; // FILE_STANDARD_INFORMATION: AllocationSize, EndOfFile, ...
    st = NtQueryInformationFile(f, &iosb, fsi, sizeof(fsi), 5 /*FileStandardInformation*/);
    if (st < 0) {
        kv("NtQueryInformationFile failed: ", (u32)st);
        NtClose(f);
        return 0;
    }
    u64 filesz = *(u64 *)(fsi + 8);
    u8 *file = (u8 *)RtlAllocateHeap(process_heap(), 0, filesz);
    if (!file) {
        NtClose(f);
        return 0;
    }
    i64 off = 0;
    st = NtReadFile(f, 0, 0, 0, &iosb, file, (u32)filesz, &off, 0);
    NtClose(f);
    if (st < 0) {
        kv("NtReadFile failed: ", (u32)st);
        return 0;
    }
    u64 nt = *(u32 *)(file + 0x3C);
    u64 opt = nt + 24;
    u64 image_base = *(u64 *)(file + opt + 24);
    g_target_size = *(u32 *)(file + opt + 56);
    u32 size_of_headers = *(u32 *)(file + opt + 60);
    g_tls_rva = *(u32 *)(file + opt + 112 + 9 * 8);
    u32 reloc_rva = *(u32 *)(file + opt + 112 + 5 * 8);
    u16 nsec = *(u16 *)(file + nt + 6);
    u64 secs = (u64)file + nt + 24 + *(u16 *)(file + nt + 20);

    // Private pages at the preferred base (fall back to anywhere + relocs).
    void *base = (void *)image_base;
    u64 region = g_target_size;
    st = NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &region, 0x3000 /*RESERVE|COMMIT*/, 0x40 /*RWX*/);
    if (st < 0 || base != (void *)image_base) {
        base = 0;
        region = g_target_size;
        st = NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &region, 0x3000, 0x40);
        if (st < 0) {
            kv("NtAllocateVirtualMemory failed: ", (u32)st);
            return 0;
        }
    }
    g_target = (u64)base;
    i64 delta = (i64)(g_target - image_base);
    kv("target mapped at: ", g_target);
    kv("  delta: ", (u64)delta);

    memcpy(base, file, size_of_headers < filesz ? size_of_headers : filesz);
    for (u16 i = 0; i < nsec; i++) {
        u64 s = secs + i * 40;
        u32 va = *(u32 *)(s + 12);
        u32 rs = *(u32 *)(s + 16);
        u32 ro = *(u32 *)(s + 20);
        if (rs) memcpy((u8 *)base + va, file + ro, rs);
    }

    if (delta != 0 && reloc_rva) {
        u64 p = (u64)base + reloc_rva;
        u64 applied = 0;
        for (;;) {
            u32 prva = *(u32 *)p;
            u32 bsz = *(u32 *)(p + 4);
            if (!prva || bsz < 8) break;
            for (u32 j = 8; j + 2 <= bsz; j += 2) {
                u16 e = *(u16 *)(p + j);
                u32 typ = e >> 12;
                u64 a = g_target + prva + (e & 0xFFF);
                if (typ == 10) {
                    *(u64 *)a += (u64)delta;
                    applied++;
                } else if (typ == 3) {
                    *(u32 *)a += (u32)delta;
                    applied++;
                }
            }
            p += bsz;
        }
        kv("  relocs applied: ", applied);
    }
    RtlFreeHeap(process_heap(), 0, file);
    return 1;
}

// --------------------------------------------- target import binding (kernel32 etc.)

static void *find_export(u64 base, const char *name) {
    u64 nt = base + *(u32 *)(base + 0x3C);
    u64 opt = nt + 24;
    u32 er = *(u32 *)(opt + 112 + 0 * 8);
    if (!er) return 0;
    u64 exp = rva2va(er);
    u32 nf = *(u32 *)(exp + 20);
    u32 nn = *(u32 *)(exp + 24);
    u32 aof = *(u32 *)(exp + 28);
    u32 aon = *(u32 *)(exp + 32);
    for (u32 i = 0; i < nn; i++) {
        const char *n = (const char *)rva2va(*(u32 *)(rva2va(aon) + i * 4));
        u64 j = 0;
        for (;; j++) {
            char c1 = name[j], c2 = n[j];
            if (c1 != c2) break;
            if (c1 == 0) {
                u16 ord = *(u16 *)(rva2va(*(u32 *)(exp + 36)) + i * 2);
                if (ord >= nf) return 0;
                return (void *)rva2va(*(u32 *)(rva2va(aof) + ord * 4));
            }
        }
    }
    return 0;
}

static int bind_target_imports(void) {
    u64 nt = g_target + *(u32 *)(g_target + 0x3C);
    u64 opt = nt + 24;
    u32 ir = *(u32 *)(opt + 112 + 1 * 8);
    if (!ir) return 1;
    u64 d = rva2va(ir);
    for (u32 di = 0;; di++, d += 20) {
        u32 oft = *(u32 *)d;
        u32 name_rva = *(u32 *)(d + 12);
        u32 ft = *(u32 *)(d + 16);
        if (!oft && !name_rva && !ft) break;
        const char *dll = (const char *)rva2va(name_rva);
        wchar16_t wname[64];
        u32 i = 0;
        for (; dll[i] && i < 60; i++) wname[i] = (wchar16_t)(u8)dll[i];
        wname[i] = 0;
        UNICODE_STRING dn;
        RtlInitUnicodeString(&dn, wname);
        HANDLE mod = 0;
        NTSTATUS st = LdrLoadDll(0, 0, &dn, &mod);
        if (st < 0) {
            print("LdrLoadDll failed for ");
            print(dll);
            print("\n");
            return 0;
        }
        u64 ilt = rva2va(oft ? oft : ft);
        for (u32 k = 0;; k++) {
            u64 e = *(u64 *)(ilt + k * 8);
            if (!e) break;
            void *fn = 0;
            if (e & 0x8000000000000000ULL) {
                st = LdrGetProcedureAddress(mod, 0, (u32)(e & 0xFFFF), &fn);
            } else {
                const char *fnname = (const char *)rva2va((u32)e) + 2;
                ANSI_STRING as;
                u32 l = 0;
                while (fnname[l]) l++;
                as.Length = (u16)l;
                as.MaximumLength = (u16)(l + 1);
                as.Buffer = (char *)fnname;
                st = LdrGetProcedureAddress(mod, &as, 0, &fn);
            }
            if (st < 0 || !fn) {
                print("import resolve failed\n");
                return 0;
            }
            *(u64 *)(rva2va(ft) + k * 8) = (u64)fn;
        }
    }
    return 1;
}

// Follow the call from LdrpHandleTlsData to LdrpAllocateTlsEntry (matched by
// prologue), then decode its first `lea rcx,[rip+x]` -> LdrpTlsList.
static u64 find_ldrp_tls_list(u64 ldrp_handle_tls_data) {
    static const u8 PROL[] = {0x4c, 0x89, 0x4c, 0x24, 0x20, 0x4c, 0x89, 0x44,
                              0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x53,
                              0x56, 0x57};
    for (u64 o = 0; o < 0x600; o++) {
        const u8 *p = (const u8 *)(ldrp_handle_tls_data + o);
        if (*p != 0xE8) continue;
        i32 rel = *(i32 *)(p + 1);
        u64 callee = (u64)(p + 5) + (i64)rel;
        u64 j = 0;
        for (; j < sizeof(PROL); j++)
            if (*(const u8 *)(callee + j) != PROL[j]) break;
        if (j < sizeof(PROL)) continue;
        // callee is LdrpAllocateTlsEntry; find `lea rcx,[rip+x]`
        for (u64 q = 0; q < 0x180; q++) {
            const u8 *r = (const u8 *)(callee + q);
            if (r[0] == 0x48 && r[1] == 0x8D && r[2] == 0x0D) {
                i32 r2 = *(i32 *)(r + 3);
                return (u64)(r + 7) + (i64)r2;
            }
        }
    }
    return 0;
}

// -------------------------------------------------- LdrpHandleTlsData scan

// Win11 22621 ntdll!LdrpHandleTlsData prologue (from cdb disasm):
//   4c 8b dc          mov r11,rsp
//   49 89 5b 10       mov [r11+10h],rbx
//   49 89 73 18       mov [r11+18h],rsi
//   57 41 54 41 55 41 56 41 57
//   48 81 ec 00 01 00 00  sub rsp,100h
//   48 8b 05 <rel32>  mov rax,[__security_cookie]
//   48 33 c4          xor rax,rsp
//   48 89 84 24 f0 00 00 00
//   48 8b f9          mov rdi,rcx
static const u8 SIG[] = {0x4c, 0x8b, 0xdc, 0x49, 0x89, 0x5b, 0x10, 0x49,
                         0x89, 0x73, 0x18, 0x57, 0x41, 0x54, 0x41, 0x55,
                         0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xec, 0x00,
                         0x01, 0x00, 0x00};
static const u8 SIG2[] = {0x48, 0x8b, 0x05, 0, 0, 0, 0, 0x48, 0x33, 0xc4,
                          0x48, 0x89, 0x84, 0x24, 0xf0, 0x00, 0x00, 0x00,
                          0x48, 0x8b, 0xf9};
static const u8 SIG2_MASK[] = {1, 1, 1, 0, 0, 0, 0, 1, 1, 1,
                               1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

static u64 scan_ldrp_handle_tls_data(u64 ntdll_base) {
    u64 nt = ntdll_base + *(u32 *)(ntdll_base + 0x3C);
    u64 opt = nt + 24;
    u16 nsec = *(u16 *)(nt + 6);
    u64 secs = opt + *(u16 *)(nt + 20);
    for (u16 i = 0; i < nsec; i++) {
        u64 s = secs + i * 40;
        char nm[9];
        memcpy(nm, (void *)s, 8);
        nm[8] = 0;
        if (!(nm[0] == '.' && nm[1] == 't' && nm[2] == 'e')) continue;
        u32 vs = *(u32 *)(s + 8);
        u64 va = ntdll_base + *(u32 *)(s + 12);
        for (u64 o = 0; o + sizeof(SIG) + sizeof(SIG2) < vs; o++) {
            const u8 *p = (const u8 *)(va + o);
            u64 j = 0;
            for (; j < sizeof(SIG); j++)
                if (p[j] != SIG[j]) break;
            if (j < sizeof(SIG)) continue;
            const u8 *q = p + sizeof(SIG);
            for (j = 0; j < sizeof(SIG2); j++)
                if (SIG2_MASK[j] && q[j] != SIG2[j]) break;
            if (j == sizeof(SIG2)) return (u64)p;
        }
    }
    return 0;
}

// ------------------------------------------------------------------ main

typedef NTSTATUS(NTAPI *LdrpHandleTlsData_t)(void *entry);

static u8 g_fake_entry[0x200]; // zero-initialized LDR_DATA_TABLE_ENTRY stand-in

static volatile u32 g_thread_arr_val = 0xFFFFFFFF;
static volatile u32 g_thread_read1 = 0xFFFFFFFF;
static volatile u32 g_thread_read2 = 0xFFFFFFFF;

typedef int(NTAPI *read_fn)(void);
typedef void(NTAPI *write_fn)(int);

static u32 NTAPI thread_proc(void *p) {
    (void)p;
    u64 arr = __readgsqword(0x58);
    u64 block = *(u64 *)arr; // slot 0
    g_thread_arr_val = block ? *(u32 *)block : 0xEEEEEEEE;
    read_fn tr = (read_fn)find_export(g_target, "tls_read");
    write_fn tw = (write_fn)find_export(g_target, "tls_write");
    g_thread_read1 = (u32)tr();
    tw(99);
    g_thread_read2 = (u32)tr();
    RtlExitUserThread(0);
    return 0;
}

static u64 g_slot = 0xFFFFFFFF;

// Alias slot 0 -> the target's (ntdll-owned) block, then exit. Tests whether
// ntdll teardown frees blocks per its own TLS list (safe) or per array slot
// (double-free -> heap fail-fast).
static u32 NTAPI thread_alias_proc(void *p) {
    (void)p;
    u64 arr = __readgsqword(0x58);
    u64 target_block = *(u64 *)(arr + g_slot * 8);
    *(u64 *)arr = target_block;
    g_thread_arr_val = *(u32 *)(*(u64 *)arr); // hardcoded-slot-0 style read
    RtlExitUserThread(0);
    return 0;
}

static void fail(const char *msg, u32 code) {
    print("FAIL: ");
    print(msg);
    print("\n");
    NtTerminateProcess((HANDLE)-1, code);
}

void probe_main(void) {
    print("== tlsprobe start ==\n");
    print("loaded modules:\n");
    list_modules();
    int host_tls = count_host_tls();
    print("host TLS module count: ");
    print_dec((u64)host_tls);
    print("\n");

    // Map the target next to the probe binary (cwd-relative NT path).
    u64 pp = peb_pp();
    u16 cwdlen = *(u16 *)(pp + 0x38);
    wchar16_t *cwd = *(wchar16_t **)(pp + 0x38 + 8);
    static wchar16_t path[512];
    u32 i = 0;
    const wchar16_t *pfx = L"\\??\\";
    for (; pfx[i]; i++) path[i] = pfx[i];
    for (u32 j = 0; j < cwdlen / 2; j++) path[i++] = cwd[j];
    if (i > 0 && path[i - 1] != L'\\') path[i++] = L'\\';
    const wchar16_t *sfx = L"target.dll";
    for (u32 j = 0; sfx[j]; j++) path[i++] = sfx[j];
    path[i] = 0;

    if (!map_target(path)) fail("map target", 2);
    if (!g_tls_rva) fail("target has no TLS dir", 3);

    u64 ntdll_entry = find_module("ntdll.dll");
    if (!ntdll_entry) fail("ntdll not in LDR", 4);
    u64 ntdll_base = *(u64 *)(ntdll_entry + LDR_DLLBASE);
    kv("ntdll base: ", ntdll_base);
    u64 fn = scan_ldrp_handle_tls_data(ntdll_base);
    if (!fn) fail("LdrpHandleTlsData signature not found", 5);
    kv("LdrpHandleTlsData: ", fn);
    kv("  (rva): ", fn - ntdll_base);

    u64 tlsdir = rva2va(g_tls_rva);
    print("tls dir fields in mapped image:\n");
    kv("  template start: ", *(u64 *)(tlsdir + 0));
    kv("  template end:   ", *(u64 *)(tlsdir + 8));
    kv("  index addr:     ", *(u64 *)(tlsdir + 16));
    kv("  callbacks addr: ", *(u64 *)(tlsdir + 24));
    kv("  MZ check: ", *(u16 *)g_target);
    kv("  NT sig check: ", *(u32 *)(g_target + *(u32 *)(g_target + 0x3C)));

    // Fake LDR entry: only DllBase and SizeOfImage are read by the function
    // (verified by disassembly: +0x30 and the +0x10C field compare).
    *(u64 *)(g_fake_entry + LDR_DLLBASE) = g_target;
    *(u64 *)(g_fake_entry + LDR_SIZEOFIMAGE) = g_target_size;

    LdrpHandleTlsData_t reg = (LdrpHandleTlsData_t)fn;
    NTSTATUS st = reg(g_fake_entry);
    kv("LdrpHandleTlsData returned: ", (u32)st);
    if (st < 0) fail("registration failed", 6);

    kv("fake entry TlsIndex: ", *(u16 *)(g_fake_entry + LDR_TLSINDEX));
    u64 index_addr = *(u64 *)(tlsdir + 16);
    kv("image _tls_index DWORD: ", *(u32 *)index_addr);

    // Main thread retrofit check.
    u64 arr = __readgsqword(0x58);
    u64 block0 = *(u64 *)arr;
    kv("main thread array slot0 block: ", block0);
    if (block0) kv("main thread slot0 value: ", *(u32 *)block0);

    // Now pull in kernel32 (drags in kernelbase, which HAS a TLS directory):
    // it must integrate natively and take the next slot.
    UNICODE_STRING k32;
    RtlInitUnicodeString(&k32, L"kernel32.dll");
    HANDLE k32h = 0;
    st = LdrLoadDll(0, 0, &k32, &k32h);
    kv("LdrLoadDll(kernel32): ", (u32)st);
    list_modules();

    arr = __readgsqword(0x58);
    kv("main thread slot0 after k32 load: ", *(u32 *)(*(u64 *)arr));

    if (!bind_target_imports()) fail("bind imports", 7);

    // New thread: ntdll must give it the target's block natively.
    HANDLE th = 0;
    CLIENT_ID cid;
    st = RtlCreateUserThread((HANDLE)-1, 0, 0, 0, 0x100000, 0x10000, thread_proc, 0, &th, &cid);
    if (st < 0) fail("RtlCreateUserThread", 8);
    NtWaitForSingleObject(th, 0, 0);
    NtClose(th);
    kv("thread slot0 value: ", g_thread_arr_val);
    kv("thread tls_read #1 (want 42): ", g_thread_read1);
    kv("thread tls_read #2 (want 99): ", g_thread_read2);

    // Heap hammer: prove the native thread teardown freed nothing foreign.
    void *heap = process_heap();
    for (int k = 0; k < 5000; k++) {
        void *p = RtlAllocateHeap(heap, 0, 1024);
        if (!p) fail("heap corrupt", 9);
        RtlFreeHeap(heap, 0, p);
    }

    read_fn cb = (read_fn)find_export(g_target, "cb_count");
    kv("cb_count (+1 per thread attach): ", (u32)cb());
    kv("main tls_read (want 42): ", (u32)((read_fn)find_export(g_target, "tls_read"))());

    // Phase 3 (DISABLED, deterministically heap-fail-fasts): aliasing slot 0
    // to the target's block in ntdll's own array is NOT teardown-safe.
    // Measured: LdrpFreeTls frees per-array-slot, so the aliased pointer is
    // double-freed at thread exit -> LdrShutdownThread -> RtlFreeHeap ->
    // heap fail-fast 0xC0000374. Flip to 1 to reproduce.
    static const int RUN_ALIAS_TEST = 0;
    if (RUN_ALIAS_TEST) {
        HANDLE th3 = 0;
        CLIENT_ID cid3;
        st = RtlCreateUserThread((HANDLE)-1, 0, 0, 0, 0x100000, 0x10000, thread_alias_proc, 0, &th3, &cid3);
        if (st < 0) fail("RtlCreateUserThread #3", 10);
        NtWaitForSingleObject(th3, 0, 0);
        NtClose(th3);
        kv("phase3 aliased slot0 value (want 42): ", g_thread_arr_val);
        print("phase3: alias thread exited, heap alive (unexpected!)\n");
    }

    // Phase 4: slot-0 graft. The probe carries a TLS directory, so slot 0
    // belongs to the process image (us) — kernelbase lands at slot 1. Rewrite
    // our LdrpTlsList entry so slot-0 blocks are built from the target's
    // template and its callbacks; ntdll then does per-thread TLS natively.
    {
        u64 tlsp = find_ldrp_tls_list(fn);
        kv("LdrpTlsList: ", tlsp);
        if (!tlsp) fail("LdrpTlsList not found", 12);
        u64 head = tlsp;
        u64 our = 0;
        for (u64 e = *(u64 *)head; e && e != head; e = *(u64 *)e) {
            if (*(u64 *)(e + 0x20) == (u64)&_tls_index) {
                our = e;
                break;
            }
        }
        kv("our TLS entry: ", our);
        if (!our) fail("own TLS entry not found", 13);
        u64 tstart = *(u64 *)(tlsdir + 0);
        u64 tend = *(u64 *)(tlsdir + 8);
        u64 tcbs = *(u64 *)(tlsdir + 24);
        u32 tzf = *(u32 *)(tlsdir + 32);
        *(u64 *)(our + 0x10) = tstart;
        *(u64 *)(our + 0x18) = tend;
        *(u64 *)(our + 0x28) = tcbs;
        *(u32 *)(our + 0x30) = tzf;
        _tls_used.AddressOfCallBacks = tcbs; // LDR-walk callback path
        *(u32 *)index_addr = 0;              // target now means slot 0
        // fix up THIS thread's slot-0 block content (allocated at process
        // start from our empty graft template)
        u64 arr4 = __readgsqword(0x58);
        memcpy((void *)(*(u64 *)arr4), (void *)tstart, (u32)(tend - tstart));

        HANDLE th4 = 0;
        CLIENT_ID cid4;
        g_thread_arr_val = g_thread_read1 = g_thread_read2 = 0xFFFFFFFF;
        st = RtlCreateUserThread((HANDLE)-1, 0, 0, 0, 0x100000, 0x10000, thread_proc, 0, &th4, &cid4);
        if (st < 0) fail("RtlCreateUserThread #4", 14);
        NtWaitForSingleObject(th4, 0, 0);
        NtClose(th4);
        kv("graft: thread slot0 value (want 42): ", g_thread_arr_val);
        kv("graft: thread tls_read (want 42): ", g_thread_read1);
        kv("graft: thread tls_write/read (want 99): ", g_thread_read2);
        kv("graft: cb_count (want >=1 if native): ", (u32)cb());
        typedef u64(NTAPI *u64_fn)(void);
        kv("graft: cb handle: ", ((u64_fn)find_export(g_target, "cb_handle_value"))());
        kv("       probe base: ", *(u64 *)(peb() + 0x10));
        for (int k = 0; k < 5000; k++) {
            void *p = RtlAllocateHeap(heap, 0, 1024);
            if (!p) fail("heap corrupt after graft thread exit", 15);
            RtlFreeHeap(heap, 0, p);
        }
        print("graft: thread exited, heap alive\n");
    }

    print("== PROBE OK ==\n");
    NtTerminateProcess((HANDLE)-1, 0);
}
