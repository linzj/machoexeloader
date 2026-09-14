# elldr — 用户态 ELF (x86_64) 可执行文件加载器

`elldr` 是 mldr(Mach-O 版)与 peldr(PE 版)的 Linux 对应物:自己实现的 **mini-ld.so**。
在用户态完成 ELF 的解析、段映射、GOT/PLT 重定位与宿主 glibc 桥接、local-exec TLS
布局、构造器注册与入口跳转,**不经过 `execve`、也不依赖内核 exec 加载目标镜像**。
加载完成后在专用线程上构造内核风格的初始栈,把 PC 设为 ELF entry 并跳转执行。

```
elldr [-v] [-e] <executable> [args...]

  -v      在 stderr 上输出详细的镜像/映射/绑定/TLS 诊断
  -e      只加载和准备,不执行目标(用于验证加载全流程)
```

最终目标已实测:**Claude Code 的 linux-x64 原生二进制**(Bun 单文件 EXE,214MB,
3 段、10 个 phdr、495+66 条重定位、9481 处 local-exec TLS 访问、12.8MB 栈需求):

```
elldr claude --version   →  2.1.260 (Claude Code)(与原生逐字节一致,exit 0)
elldr claude --help      →  304 行帮助,与原生 diff 为空
elldr claude -p "say hi" →  网络栈路径与原生行为一致(HTTP/DNS/epoll 原生可用)
elldr -e claude          →  全量加载:561 重定位、8 个 ifunc、6 个 NEEDED 桥接
```

## 加载流程

```
elldr [-v] [-e] <目标> [args...]
 1. 解析(elf.rs):Ehdr/Phdr、PT_LOAD/PT_TLS/PT_GNU_STACK/PT_GNU_EH_FRAME/PT_DYNAMIC、
    dynsym/dynstr、.gnu.version/verneed、DT_RELA+DT_JMPREL、INIT/FINI_ARRAY;仅接受
    x86_64 ET_EXEC(非 PIE;ET_DYN/PIE 的动态 TLS 模型不支持,直接报错)
 2. 映射(image.rs):mmap(PROT_NONE, MAP_FIXED_NOREPLACE) 预留整段 → 逐 LOAD
    MAP_FIXED|MAP_PRIVATE 文件映射(页对齐 vaddr/offset,bss 尾匿名补零,
    R/RX/RW 一次到位;无 GNU_RELRO 时无需收尾);loader 自身必须为 PIE(运行时断言)
 3. 重定位(imports.rs):COPY 先行(宿主符号内容拷入目标镜像,并记录本地地址) →
    GLOB_DAT/R_X86_64_64/JUMP_SLOT(shim 表 → dlvsym 带版本 → dlsym(RTLD_DEFAULT),
    weak 未解析=0 并日志;COPY 过的符号后续引用一律指向本地副本,glibc 语义)→
    最后逐个执行 IRELATIVE resolver(irelative 的 addend 对 ET_EXEC 即绝对地址)
 4. 依赖(loader.rs):六个 NEEDED 全部走宿主桥接(librt/libpthread/libdl 在
    glibc 2.34+ 为空壳;统一经 RTLD_DEFAULT 解析符号);宿主预加载 libgcc_s.so.1
    (供 backtrace()/unwinder 使用)
 5. TLS(tls.rs):核心技法——非 PIE 目标的 TLS 是 local-exec 烘焙偏移,假设自己的
    TLS 块在 [TP - align16(memsz), TP)(实测目标 9481 处 fs 负偏移全部落在此区间)。
    elldr 自身 PT_TLS 用 64KB pad 撑出主镜像块 → 每个要执行目标代码的线程启动时:
    tp=arch_prctl(GET_FS) → base=tp-align16(目标 memsz) → memcpy 目标 tdata 模板 →
    清零 tbss → 目标全部烘焙访问命中;运行时以 dl_iterate_phdr 首项的 dlpi_tls_data
    自检"自身块覆盖目标块",不满足即报错(防无 pad 重编译)
 6. 构造器(glibc ≥2.34 由 ld.so 负责,elldr 扮演该角色):preinit_array →
    DT_INIT + INIT_ARRAY(以 (argc,argv,envp) 调用);FINI_ARRAY/DT_FINI 经
    __cxa_atexit 注册,exit 时逆序执行
 7. 入口(entry.rs):裸 pthread_create(栈 = max(PT_GNU_STACK 0xc35000, 8MB))→
    线程内装 TLS → 在真实栈可用的顶部构造 [argc][argv][NULL][envp][NULL][auxv]
    (AT_PHDR/AT_ENTRY/AT_EXECFN=目标路径/AT_RANDOM 等,rsp 16 对齐)→
    naked asm: mov rsp,帧; xor edx,edx; jmp entry(rdx=rtld_fini=0)
 8. 启动 shim(sim_libc_start_main):目标 _start 调 __libc_start_main@plt 进入我们的
    实现——跑构造器 → main(argc,argv,envp) → 宿主 libc exit(ret):stdio 冲刷、
    atexit(含目标的 __cxa_atexit 注册)全部按原生语义执行
```

## 注入目标 GOT 的 shim 表(对应 peldr 的 IAT shim / mldr 的 shim_lookup)

| 符号 | 行为 |
|---|---|
| `__libc_start_main` | elldr 自己的启动实现(构造器 → main → 宿主 exit) |
| `pthread_create` | 包装 start routine:新线程先装目标 TLS 模板再执行(Bun/JSC 线程池) |
| `dlsym` | RTLD_DEFAULT/RTLD_NEXT:先查目标自身导出(ifunc 符号跑 resolver),再落宿主全局——宿主 RTLD_NEXT 无法识别目标镜像内的调用者,返回 NULL 会把 Bun 的 quick_exit 解析成空指针 |
| `dl_iterate_phdr` | 先把目标镜像(dlpi_addr=0、原始 phdrs、dlpi_tls_data=TP-目标块、名称=空)回调一次,再转发宿主;libgcc/Bun 的 unwinder 靠它找到目标 .eh_frame 的 FDE |
| `dladdr` | 目标范围内的 PC 解析到目标路径/最近导出符号 |
| `readlink`/`readlinkat`/`open`/`open64`/`openat`/`openat64`/`fopen`/`fopen64` | `/proc/self/exe` → 目标路径(Bun selfExePath) |
| `syscall` | 同上路径的 readlinkat/openat/statx 重定向(Zig 风格直接调用 libc syscall() 的路径) |
| `program_invocation_name`/`program_invocation_short_name`(数据) | 启动时改写宿主 libc 内指针 + 目标 GOT 指向 elldr 持有的目标名 |
| `__tls_get_addr` | 转发宿主;被调用则报错级日志(正常不可达;出现即目标用了动态 TLS) |

诊断:环境变量 `ELLDR_LOG=<path>` 将全部诊断落文件;`-v` 打开详细日志;崩溃时
`-v` 下安装 SIGSEGV/SIGBUS/SIGILL 报告器(寄存器 + 目标内定位 + 线程 TLS 状态)。

## 代码结构

| 文件 | 职责 |
|---|---|
| `src/elf.rs` | ELF64 解析(phdrs/dynamic/dynsym/versions/RELA/TLS/GNU hash) |
| `src/image.rs` | 地址空间预留、段映射、权限落地、PIE 断言 |
| `src/loader.rs` | 编排:解析→映射→shim 初始化→绑定→TLS→构造器→入口 |
| `src/imports.rs` | 重定位:COPY→GLOB_DAT/64/JUMP_SLOT→IRELATIVE,宿主桥接缓存 |
| `src/shim.rs` | GOT shim 表、启动实现、pthread 包装、dl 自省、/proc/self/exe 重写 |
| `src/tls.rs` | local-exec TLS 主块技法:pad 自检 + 每线程模板安装 |
| `src/entry.rs` | 裸线程、伪内核初始栈、naked 跳转、崩溃报告器 |
| `src/sys.rs` | 最小裸 libc 绑定(mmap/dl/pthread/arch_prctl)+ 裸 fd 日志 |
| `src/diag.rs` | `vlog!`/`rerr!`(裸 write,目标线程禁用 Rust std TLS) |

零外部 crate 依赖;测试目标用 cc 编译(`-no-pie`,与真实目标同走 local-exec TLS)。

## Linux x86_64 上实测确认的实现要点

- **local-exec TLS 是最大障碍**:非 PIE glibc 程序的 TLS 访问被链接器松弛成
  `%fs:` 直接偏移,假设自己的块在 `[TP - align16(memsz), TP)`。宿主进程的主镜像
  TLS 块就在这个位置,所以 elldr 让自己的 PT_TLS 足够大(64KB pad),目标线程启动
  时把目标模板原地填进去。**代价是目标线程上 std 的 TLS 变量(位于块顶部)会被
  覆盖**——因此目标线程上的 elldr 代码禁用一切 std TLS 设施(日志走裸 write、
  用 Mutex/OnceLock,不用 std::io/std::thread/std::process/std::panic)。
- **glibc ≥ 2.34 的 crt 传 init=NULL**:构造器改由 ld.so 调用,`__libc_csu_init`
  已不存在;elldr 必须自己跑 preinit/DT_INIT/init_array(否则 Bun/JSC 的 19 个
  构造器不执行),并自己注册 fini_array。
- **IRELATIVE 的 addend 对 ET_EXEC 是绝对地址**(l_addr=0),写成 base+addend
  会跳到垃圾代码;COPY 重定位后,目标内对同一符号的 GLOB_DAT 引用必须指向本地
  副本地址(glibc 语义,`&stdout`/`&environ` 两条访问路径才一致)。
- **栈顶不能用 pthread_getattr_np 的 top**:返回值包含线程顶部的 TCB/静态 TLS
  区,把伪初始栈放在那里会踩 TCB——实测表现为 `*** stack smashing detected ***`
  (vfprintf 的帧跑到了 TLS 区里)。正确做法:线程刚启动时以自己的栈帧位置为基准
  向下让出几十字节,这就是可用的初始 sp。
- **dlsym(RTLD_NEXT) 在目标镜像里必须 shim**:宿主 ld.so 用返回地址找调用者所在
  的 link_map,找不到目标镜像就返回 NULL——Bun 用它懒解析 `quick_exit`,空指针
  调用直接段错误。RTLD_DEFAULT 同理需要先查目标自身导出。
- **dl_iterate_phdr 必须能看到目标镜像**(dlpi_addr=0 + 原始 phdrs,dlpi_name
  与原生一致为空串):Bun/Zig 的 unwinder 与 JSC 自省依赖它,否则 C++ 异常与
  backtrace 找不到 FDE。
- **`/proc/self/exe` 即身份**:Bun 的 selfExePath 走 readlink/readlinkat;Zig 风格
  的 `syscall()` 包装也要一并重定向;`AT_EXECFN`(伪栈)同供。
- **PT_GNU_STACK 是栈需求**:目标要 12.8MB,按它创建线程栈;目标代码用 libc 的
  `pthread_getattr_np` 做栈边界检测,行为与原生一致。
- **无 GNU_RELRO 时映射即定稿**:三段权限(R/RX/RW)一次映射到位,没有收尾期;
  Bun 的 JIT 页由目标自己 mmap RWX,Linux 无 W^X 阻碍。

## 验证

```
cd elldr && ./tests/run_tests.sh
```

对每个目标分别原生执行与 elldr 执行,逐项 diff stdout 与退出码:

- `hello` / `hello a b c` / `hello "a b" c` — 参数与 argv[0] 传递、伪栈保真
- `exitcode 42|0` — 退出码透传
- `tls` — `__thread` 初值/BSS/读写(local-exec 烘焙偏移路径)
- `threads` — pthread_create ×2、每线程 TLS 隔离(pthread 包装 + 每线程装模板)
- `ctor` — 构造器次序(ctor 101/102 → main → atexit → dtor)
- `ifunc` — IRELATIVE resolver(目标自身 ifunc + 宿主 glibc ifunc)
- `reloc` — .data 函数指针表(R_X86_64_64)
- `phdr` — dl_iterate_phdr 看到自身镜像 + readlink(/proc/self/exe) 指向目标
- `fork` — fork+exec 子进程路径
- `claude-load-only` — 对 214MB 目标做 `elldr -e` 全量加载
- `claude-exec-version` / `claude-exec-help` — 与原生逐字节 diff(本环境允许原生
  执行,对照比 mldr/peldr 更强)

`claude-*` 依赖 Claude Code 的原生二进制。默认在以下位置探测(可用 `CLAUDE_BIN`
指定):`tmp/claude-code/node_modules/@anthropic-ai/claude-code-linux-x64/claude`,
或 `~/.local/share/claude/versions/` 下最新版本。缺失时自动跳过。

手工核对:`elldr -v -e <target>` 的输出与 `readelf -l/-d/-r` 交叉比对。

## 已知限制

- 仅支持 x86_64 Linux、仅 ET_EXEC(非 PIE)目标;不支持强制重定位(EXEC 的代码
  含绝对地址,不可搬移);loader 自身必须为 PIE
- 目标 PT_TLS 块大小上限由 64KB pad 决定,超限报错
- 出现任何 TLS 动态重定位(DTPMOD/TLSGD/…)的目标直接报错,不做静默降级
- 运行时 `dlopen` 加载的用户 .so / 插件符号可见性未特化(宿主 dlopen 可用,
  但 .so 反向引用目标导出暂不可见)
- `-e` 会执行 IRELATIVE resolver(与 ld.so 语义一致),不做纯静态检查
