# pldr — ntdll-only 零 shim 的 PE 用户态加载器（实验）

peldr 路线的替代骨架：无 CRT、只静态链接 ntdll、只加载（~550 行单文件）。
驱动脚本是仓库根的 `scripts/runclaude.sh`（Windows 默认走它；`RUNCLAUDE_LEGACY=1`
回退 peldr 的 shim 模式）。

```
bash build.sh                 # 产出 out/pldr.exe(cl + link,只需 VS + SDK)
pldr.exe <target.exe> [args]  # 加载并跳入口
PLDR_DEBUG=1                  # 加载诊断到 stdout(默认静默,避免污染目标输出)
PLDR_WAKE_DELAY_MS=20         # 控制台唤醒延迟;0=关闭
```

## 设计

1. 进程以 pldr.exe 正常启动（OS 完整初始化它），pldr 在用户态手工映射目标：
   NtCreateFile→读文件→按节 memcpy→自己应用 .reloc（SEC_IMAGE 不可用：
   MM 首次映射时就地重定位烧进共享页，之后映射内容不可信）。
2. **TLS 槽 0 嫁接**：pldr 自带手写 `_tls_used`（模板是 4MB BSS 数组——
   SizeOfZeroFill 不计入 ntdll 的块大小计算，小模板+大 zero-fill 会让每线程块
   只有 1 字节）。进程启动时 loader 作为进程映像占槽 0（kernelbase 被挤到槽 1）；
   加载目标后改写自己在 `LdrpTlsList` 里 entry 的模板指针/回调/大小指向目标的
   TLS 目录，目标 `_tls_index` 写 0，主线程块 memcpy 目标模板并手动跑一次回调。
   之后每个新线程（含线程池）的 TLS 由 ntdll 原生分配初始化，拆卸也原生安全。
   `LdrpTlsList` 定位：`LdrpHandleTlsData` 特征码 → 顺 E8 call 找
   `LdrpAllocateTlsEntry`（prologue 匹配）→ 其第一条 lea rcx,[rip+x]。
3. PEB 补丁（ImageBaseAddress/CommandLine/ImagePathName/LDR 首条目名）要在任何
   宿主 DLL 代码跑之前完成：kernelbase 在进程初始化时就快照命令行，
   `GetCommandLineW/A` 首指令 `48 8B 05 <rel32>` 直接读 `BaseUnicodeCommandLine`
   的 Buffer 字段——覆盖该字段（长度在 -8/-6）指向伪造命令行。
4. 导入全桥接（LdrLoadDll+LdrGetProcedureAddress），.pdata 经 RtlAddFunctionTable
   注册，主线程直接跳目标入口。

## 为什么仍然有两个半 IAT 钩子（不是 shim 层回归）

- `RegisterWaitForSingleObject`+`PostQueuedCompletionStatus`：Bun 终端探测写会让
  控制台 arming wait 在驱动复位窗口内触发，唤醒包若此时被处理，挂起的读会走错
  line-mode 分支、交互输入死亡。推迟唤醒包 ~20ms 躲开。判定条件用**范围匹配**
  `overlapped ∈ [ctx, ctx+0x100)`——绝对偏移随 Bun 版本漂移（peldr shim 里硬编码的
  ctx+0x40 在 claude 2.1.276 已变成 +0xB0）。
- `QueueUserWorkItem` 跳板：**ntdll 线程池会丢弃回调地址不属于已注册模块的工作项**
  （`RtlQueueWorkItem` 内 `RtlPcToFileHeader` 失败即静默释放；`RtlAddFunctionTable`、
  手链 LDR 三链表都喂不了这个查找——地址索引走 ntdll 私有结构）。跳板函数住在
  pldr.exe（已注册模块）里，被池线程执行后再调目标回调；池线程的 TLS 由嫁接
  原生提供，所以不需要 peldr shim 那种手动 TLS 重建。

## 已知边界

- 运行时 LoadLibrary 旁的用户 DLL / 插件从 EXE 导符号：不支持（claude.exe 单文件
  用不到）。
- 特征码只在本机 Win11 22621 回归过。
- `conprobe.c`+`build_probe.sh`：控制台等待/线程池派发探针（排障用）。

`../tlsprobe/` 是更早的机制验证探针（LdrpHandleTlsData、嫁接可行性等）。
