# peldr — 用户态 PE (x86_64) 可执行文件加载器

`peldr` 是 mldr（Mach-O 版，见仓库根目录）的 Windows 对应物：自己实现的 **mini-PE-loader**。
在用户态完成 PE 的解析、段映射、基址重定位、导入解析与宿主桥接、模块 TLS 布局、
异常表注册与 PEB 伪造，**不经过 `CreateProcess`、也不依赖 ntdll 的 Ldr 加载目标镜像**。
加载完成后在专用线程上把 PC 设为入口点并跳转执行。

```
peldr [-v] [-e] [-r] [-L dir] <executable> [args...]

  -v      在 stderr 上输出详细的镜像/映射/绑定/TLS 诊断
  -e      只加载和准备，不执行目标（用于验证加载全流程）
  -r      强制重定位（不在首选 ImageBase 上加载，用于验证 .reloc 路径）
  -L dir  额外的 DLL 搜索目录
```

最终目标已实测：**Claude Code 的 win32-x64 原生二进制**（Bun 编译的单文件 EXE，227MB，
13 段、78,997 条 unwind、约 23KB `__declspec(thread)` 模板）：

```
peldr claude.exe --version   →  2.1.270 (Claude Code)
peldr claude.exe --help      →  完整帮助，exit 0
peldr -r claude.exe --version → 同上（全部镜像重定位后）
peldr claude.exe -p "say hi in one word" →  Hi   （真实会话：JS 运行时 + 网络 + API）
```

## 加载流程

```
peldr [-v] [-e] [-r] <目标> [args...]
 1. 解析(pe.rs):DOS/NT/可选头、段表、16 个数据目录;导入(name+ordinal)、
    延迟导入、导出(含 forwarder 字符串)、.reloc、TLS 目录、.pdata
 2. 映射(image.rs):VirtualAlloc 保留整段(优先 ImageBase,不可用则任意地址并应用
    .reloc,支持 DIR64/HIGHLOW)→ 整段 commit → 拷贝 headers 与原始段数据 →
    记录每段最终保护,导入/TLS 写完后统一 reprotect
 3. 依赖(loader.rs):目标目录(与 -L 目录)里找到的用户 DLL 由 peldr 自己递归解析
    并映射(自解析导出表/IAT/异常表);%SystemRoot% 下的系统 DLL 桥接到宿主进程
    已加载的副本(LoadLibrary+GetProcAddress,带正/负缓存)
    —— 与 mldr "用户 dylib 自加载 / 系统库借宿主" 完全对应
 4. 导入绑定(imports.rs):逐项解析 IAT——自映射导出(含 forwarder 链)→ 宿主桥接;
    命中 shim 表的导入改写为 peldr 自己的实现(见下)
 5. TLS(tls.rs):主镜像拿 slot 0(见"实测要点");加载器自身的 _tls_index 被改写
    为宿主 TLS 模块数 C;每个执行目标代码的线程重建 TLS 数组:
      [0]=目标主镜像块, [1..C)=宿主块原样, [C]=加载器块, [C+1..)=自映射 DLL 块
    线程退出前把 ntdll 原始数组指针换回
 6. 异常表:对每个自映射镜像调用 RtlAddFunctionTable(.pdata, count, base)
    (手工映射镜像在 x64 上 unwind/SEH 的必需注册)
 7. PEB 伪造(entry.rs):ImageBaseAddress、CommandLine、ImagePathName、主模块
    LDR 名改写为"目标就是本进程主镜像";宿主 CRT(msvcrt/ucrtbase)的
    GetCommandLineA/W IAT 与 _acmdln/_wcmdln 一并补丁(见"实测要点")
 8. 跳转:CreateThread(栈 = SizeOfStackReserve)→ trampoline(先挂 TLS、跑 TLS
    callbacks)→ entry()(PE 入口无参,CRT 自己从 PEB 取 argv);退出码 = 目标
    exit 码(目标 CRT 会自己 exit()/ExitProcess,加载器对其做硬退出)

 9. 运行时自映射(shim.rs):目标在运行时 LoadLibrary* 一个目标旁的用户 DLL 时,
    现场完成第 2~4、6 步(延迟加载就是走这条路)
```

## 注入到目标 IAT 的 shim 表（对应 mldr 的 shim_lookup）

| 导入名 | 行为 |
|---|---|
| `LoadLibraryA/W`、`LoadLibraryExA/W` | 先查自映射镜像 → 再尝试运行时自映射目标旁的用户 DLL → 否则透传宿主;返回后做 TLS 维护 |
| `GetProcAddress` | 自映射镜像的 base → 查 peldr 解析的导出表(含 forwarder);其它句柄透传(缓存) |
| `GetModuleHandleA/W`、`FreeLibrary` | 自映射镜像名/base 先查;`FreeLibrary` 对自映射镜像为 no-op |
| `GetModuleFileNameA/W` | `NULL`/自映射 base → 返回目标路径 |
| `GetCommandLineA/W` | 返回伪造的命令行(宿主 kernelbase 按首调缓存,必须自供) |
| `CreateThread`、`_beginthreadex` | 包装 start routine:新线程先完成 TLS 数组重建 |
| `RegisterWaitForSingleObject` | 回调跑在 ntdll 线程池线程上(不经 CreateThread),同样先重建 TLS,回调结束归还数组(Bun 的控制台输入读取走这条路) |
| `ExitProcess`、`ExitThread`、`TerminateProcess`(自身) | 先还原 ntdll TLS 数组 / 硬退出 |

诊断开关(环境变量,均为只读观测):`PELDR_TRACE_AV=1`(首次异常:寄存器+指令字节+栈转储+镜像内定位)、
`PELDR_TRACE_EXIT=1`(exit/_exit/_amsg_exit 调用点及返回地址)、`PELDR_TRACE_SOCK=1`(WSAStartup/GetHostNameW)。

## 代码结构

| 文件 | 职责 |
|---|---|
| `src/pe.rs` | PE32+ 解析(DOS/NT/可选头、段表、导入/延迟导入/导出/重定位/TLS/pdata) |
| `src/image.rs` | 地址空间保留、段映射、.reloc 应用、保护位落地 |
| `src/loader.rs` | Registry、递归依赖(用户 DLL 自映射 vs 系统库桥接)、总编排 |
| `src/imports.rs` | IAT 绑定:自映射导出/forwarder/宿主桥接 |
| `src/shim.rs` | 注入目标的 IAT shim 表 + 运行时自映射 + 冻结视图 + 诊断追踪器 |
| `src/tls.rs` | 模块 TLS 索引布局、每线程数组、宿主新模块加载后的迁移、退出还原 |
| `src/entry.rs` | PEB/LDR 伪造、命令号构造、大栈线程、跳转、崩溃过滤器 |
| `src/sys.rs` | 最小 Win32/ntdll 绑定(零 crate,手写 FFI)、TEB/PEB 访问、裸 stderr |
| `src/diag.rs` | `vlog!`/`rerr!`(裸 WriteFile,可在任何线程安全使用) |

零外部 crate 依赖(调试工具除外);测试目标用 cl.exe 编译。

## Windows x64 上实测确认的实现要点

- **主 EXE 的 TLS 假设 slot 0**:Bun/JSC 把主镜像的 thread-local 访问编译成
  `mov rax,[fs:58h]; mov rax,[rax]`(硬编码槽 0,链接器按"EXE 的 TLS 索引=0"优化)。
  手工映射时加载器自己就是进程主镜像、占着槽 0,所以 peldr 把**主镜像的 TLS 索引
  写为 0**、把**加载器自身镜像里的 `_tls_index` 改写为槽 C**、每个目标线程的数组
  里 `[0]=目标块、[C]=加载器块`——目标按 slot 0 访问正确,Rust 的 thread_local 在
  目标线程上也能继续工作。
- **kernelbase 缓存 GetCommandLineA/W 的首次调用结果**:宿主进程里任何模块(CRT
  加载等)提前调用过就会缓存加载器自己的命令行。peldr 三管齐下:加载器自身从 PEB
  直读 argv(绝不调 API)、目标 IAT 注入 GetCommandLine* shim、宿主 msvcrt/ucrtbase
  的 IAT 与 `_acmdln`/`_wcmdln` 导出数据一起改写(经 msvcrt 内部路径的 `__wgetmainargs`
  由此修好)。
- **ntdll 线程拆卸按自己的记账释放 TLS 块与数组**:换过数组的线程必须在退出前
  (以及进程退出前)把 TEB 指针换回 ntdll 原始数组,否则它在自家堆上释放陌生指针。
  进程级 ExitProcess 的 detach 阶段还会放大竞态,加载器对目标的 ExitProcess 直接
  走 `TerminateProcess(GetCurrentProcess())`(目标的 atexit 已在其 exit() 路径跑完,
  输出已冲刷,退出码不变)。
- **延迟加载辅助器用 `LoadLibraryExA/W`**(不是 LoadLibraryA/W),对应 shim 缺一不可。
- **`.pdata` 必须 RtlAddFunctionTable**(78,997 条实测);JSC/Bun 的 VEH 走 kernel32
  导入天然可用;目标无 CFG(实测 DllCharacteristics 无 GUARD_CF)。
- **运行时自映射**:延迟加载/dynamic load 在运行时找目标旁的用户 DLL,现场解析+映射
  +绑定+注册 unwind(等价 load 期逻辑),宿主搜索路径完全不同的问题由此消除。
- **线程池回调线程**:`RegisterWaitForSingleObject` 的回调在 ntdll 线程池线程上执行,
  不经 CreateThread shim(Bun 的 TUI 控制台输入读取就挂在它上面);漏掉包裹会导致
  回调读到加载器的 TLS 块 —— 表现为 TUI 渲染正常但无法输入、卡死。
- **目标线程上的加载器代码禁止使用 Rust std 的 TLS 附带设施**(stdio/panic 展开路径
  内含 thread_local);运行期日志统一走裸 WriteFile(`vlog!`/`rerr!`),panic hook 同样
  裸写。v3 之后目标线程的 Rust TLS 已保持可用,但这层防御保留。

## 验证

```
cd peldr && ./tests/run_tests.sh
```

对每个目标分别**原生执行与 peldr 执行**(同一 cmd 命令行,逐项 diff stdout 与退出码):

- `hello` / `hello a b c` / `hello "a b" c` — 参数与 argv[0] 传递、命令行引用转义
- `exitcode 42|0` — 退出码透传
- `ctor` — CRT 构造器(`.CRT$XCU`,经 CRT `_initterm` 跑)
- `tls` — `__declspec(thread)` 初值/BSS/读写
- `threads` — `CreateThread` 与 `_beginthreadex` 双路径、每线程 TLS 隔离
- `waiter` — `RegisterWaitForSingleObject` 线程池回调中的 TLS 访问
- `modname` — PEB 伪造(`GetModuleFileNameW`/`GetModuleHandleW`/argv)
- `greettest` — 依赖链:main → greet.dll → suffix.dll(自映射、跨模块 IAT)
- `greettest_delay` — `/DELAYLOAD:greet.dll`(运行时自映射路径)
- 其中 `greettest`/`hello` 另跑 `-r` 强制重定位版本
- `claude-load-only` / `claude-exec-version` / `claude-exec-help` /
  `claude-exec-version-rebased` — 对 Claude Code 的 227MB win32-x64 原生二进制

`claude-*` 依赖 Claude Code 的原生二进制,仓库不含该文件(`tmp/` 已忽略),缺失时
脚本自动跳过。要跑这四项,先下载(走代理):

```
HTTPS_PROXY=http://127.0.0.1:7899 npm install --prefix tmp/claude-code \
    @anthropic-ai/claude-code-win32-x64@2.1.270
# 二进制:tmp/claude-code/node_modules/@anthropic-ai/claude-code-win32-x64/claude.exe
```

peldr 下运行 Claude Code 的网络操作同样需要代理环境变量(`HTTPS_PROXY=...`)。

手工核对:`peldr -v <target>` 的输出与 `dumpbin /headers /imports` 交叉比对;
崩溃定位用 `tools/pe-disasm.cjs`(需 `npm i capstone-wasm`,按 RVA 反汇编):

```
node tools/pe-disasm.cjs tmp/.../claude.exe b79bef 100
```

## 已知限制

- 仅支持 x86_64 PE;目标是 EXE(依赖 DLL 可以是任意 PE DLL)
- 运行时自映射的 DLL 若带模块 TLS 目录会告警且不保证可用(加载期的自映射 DLL 支持)
- 不做 CFG 注册(实测目标无 CFG;若遇到 /guard:cf 目标需补 SetProcessValidCallTargets)
- 不做 FreeLibrary 引用计数/卸载;内存峰值约 500MB(227MB 文件 + 219MB 镜像),与 mldr 同级
- 目标是 GUI 子系统程序时可用但控制台交互按目标自身行为
