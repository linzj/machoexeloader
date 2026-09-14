# mldr — 用户态 Mach-O 可执行文件加载器

`mldr` 是一个自己实现的 **mini-dyld**:在用户态完成 Mach-O 可执行文件的解析、段映射、
依赖加载、符号绑定、fixup 处理和入口跳转,**不经过内核的 exec 加载流程,也不依赖 dyld
加载目标程序**。加载完成后把 PC 设置到入口点并跳转执行。

```
mldr [-v] [-e] [-L dir] <executable> [args...]

  -v      在 stderr 上输出详细的镜像/映射/绑定/初始化诊断
  -e      只加载和修正(fixup),不执行目标(用于验证加载全流程)
  -L dir  额外的 @rpath 搜索目录
```

## 加载流程

```
mldr [-v] [-e] <目标> [args...]
 1. 解析目标(支持 FAT,选 arm64 slice):load commands / segments / dylibs / rpaths /
    LC_MAIN / chained fixups / exports trie;非 PIE 或无签名则报错
 2. 映射:mmap 保留地址空间 → 计算 slide → MAP_FIXED 映射各段
    __TEXT 文件映射(保签名),__DATA* 修正期间可写,__LINKEDIT 只读,跳过 __PAGEZERO
 3. 依赖:磁盘上的用户 dylib 由 mldr 自己递归解析并映射(@rpath/@loader_path/
    @executable_path/绝对路径);系统库(/usr/lib、/System,只在 dyld shared cache 中)
    通过 dlopen/dlsym "借" 宿主进程已加载的副本
 4. fixup:先 rebase(镜像内),全部镜像加载完后统一 bind;支持现代
    LC_DYLD_CHAINED_FIXUPS 与经典 LC_DYLD_INFO rebase/bind/lazy opcode;weak 绑定延迟解析
 5. 符号:自加载镜像走 exports trie(回退 symtab,支持 reexport 链);系统符号走宿主 dlsym;
    ordinal 语义 0=self、-1=main、-2=flat、-3=weak、正数=依赖序号
 6. TLS:为 __DATA,__thread_vars 描述符安装 thunk(寄存器全保留的 naked asm 跳板),
    key/offset/init/size 按 dyld 布局填写;pthread 键存储每线程数据块
 7. 初始化:按依赖优先顺序执行 __TEXT,__init_offsets / __DATA,__mod_init_func
 8. 跳转:在按 LC_MAIN.stacksize 开的大栈线程上把 PC 设为
    __TEXT.vmaddr + entryoff + slide,以 entry(argc, argv, envp, apple) 调用,返回后 exit
```

## 代码结构

| 文件 | 职责 |
|---|---|
| `src/macho.rs` | Mach-O 解析(thin/fat、load commands、section、linkedit 载荷) |
| `src/image.rs` | 地址空间保留、段映射、slide、保护位落地、初始化器收集 |
| `src/loader.rs` | 依赖图:路径展开(@rpath 等)、去重、递归加载、总编排 |
| `src/fixups.rs` | chained fixups 链行走 + 经典 rebase/bind/lazy opcode 解释器 |
| `src/resolve.rs` | exports trie/symtab、两级符号解析、宿主 dlopen/dlsym 桥接(带缓存) |
| `src/tls.rs` | TLV 描述符初始化 + thunk + pthread 键块分配 |
| `src/entry.rs` | shim(_NSGetArgc/_NSGetArgv/_NSGetExecutablePath/__tlv_bootstrap…)、大栈线程、跳转 |
| `src/sys.rs` | 最小 libc 绑定(mmap/mprotect/dlopen/dlsym/pthread TSD) |

零外部 crate 依赖;测试目标用 clang 编译。

## macOS 26 (arm64) 上实测确认的实现要点

- **入口**:arm64 不再链接 crt1(SDK 里 crt1.o 只剩 x86_64),`LC_MAIN.entryoff`
  直接指向 `main`;dyld 以寄存器传参 `entry(argc=x0, argv=x1, envp=x2, apple=x3)`,
  返回后 `exit(ret)`。mldr 按同样约定跳转。
- **文件映射不允许直接带 PROT_EXEC**:即使文件已(ad-hoc)签名,MAP_FIXED 到自己的
  保留区也会 EPERM。正确做法(同 dyld):先 r--/rw- 映射,再 mprotect 加 r-x。
- **构造器**:现代二进制在 `__TEXT,__init_offsets` 里放 32 位偏移(相对 mach header),
  不是 `__mod_init_func` 指针表;两者都支持。
- **TLV 描述符**运行时布局:`{thunk(u64), key(u32@8), offset(u32@12),
  initRel(i32@16, 相对 &desc[16]), blockSize(u32@20)}`;**thunk 调用 ABI 要求除
  x0/x16/x17 外所有寄存器(含 x8、q0-q7)保持不变**,调用方会把活值跨 thunk 调用保留
  在 x8 等寄存器里;mldr 的 thunk 用 naked asm 保存/恢复全寄存器。
- **系统库磁盘无文件**:`/usr/lib/libSystem.B.dylib` 等只存在于 dyld shared cache;
  桥接策略下不需要解析 cache。

## 验证

```
./tests/run_tests.sh
```

对每个目标分别原生执行与本加载器执行,逐项 diff stdout 与退出码:

- `hello` / `hello a b c` — 参数与 argv[0] 传递
- `exitcode 42|0` — 退出码透传
- `tls` / `threads` — 单线程/多线程 TLS(pthread_create 的工作线程)
- `ctor` — 构造函数(`__init_offsets`)
- `hello_classic` — 经典 LC_DYLD_INFO fixups(`-Wl,-no_fixup_chains`)
- `greettest` — 依赖链:main → @rpath/libgreet.dylib → @loader_path/libsuffix.dylib
  (自加载 dylib、两级绑定、数据 rebase)
- `claude-load-only` — 对 Claude Code 的 207MB arm64 原生二进制(Bun/JSC,
  6 个段、96444 个 chained fixup、142 个 TLV 描述符)做 `mldr -e` 全量加载
- `claude-exec-version` — 经 mldr **完整执行**该二进制:`mldr <claude> --version`
  → `2.1.270 (Claude Code)`、`--help` 输出完整帮助、退出码 0(直接原生执行该
  二进制在本环境会被拦截,mldr 下不受影响;需要网络的操作再挂
  `HTTPS_PROXY=http://127.0.0.1:7899`)

也可手工对照:`mldr -v <target>` 的输出与 `otool -l`、`dyld_info -fixups` 交叉核对。

## 已知限制

- 仅支持普通 **arm64**(不支持 arm64e 系统二进制与 x86_64)
- 非 PIE 可执行文件拒绝加载;目标必须带 code signature(缺失时提示 `codesign -f -s -`)
- 不做 ObjC 类注册(不调用 `_objc_addImage`),纯 C/C++ 目标可用
- 不自解析 dyld shared cache;系统库符号借宿主副本,因此 `_dyld_get_image_*`
  等宿主 dyld API 只能看到宿主的镜像;目标内 `dlopen` 走宿主 dyld
- TLS 块按线程分配且不释放(与 dyld 行为一致的简化);`_NSGetArgc/_NSGetArgv/
  _NSGetExecutablePath` 由 mldr 的 shim 提供
