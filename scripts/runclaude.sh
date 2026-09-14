#!/bin/sh
# 经用户态加载器启动 claude 原生二进制:
#   macOS  -> mldr  (darwin-arm64)
#   Windows Git Bash -> peldr (win32-x64)
# 环境/flags 对齐 ~/.local/bin/claude-node:
#   DISABLE_AUTOUPDATER=1、本机代理、--setting-sources project,local
#   (排除 user settings,注入的钩子都挂在 user settings 里)、
#   --dangerously-skip-permissions;不挂任何 BUN_OPTIONS preload 钩子。
# --settings 由本脚本自带生成,不依赖其他项目:claude-code-bun 的 nohooks.json
# 属于那个项目,其 statusLine 又引用 ~/.claude/statusline-command.sh 等外部脚本。
# 生成内容与该文件等价:disableRemoteControl + attribution;statusLine 仅在
# 对应脚本存在时保留(软引用);选 [d] 时叠加 disableAllHooks。
# 启动前检测 cwd 的 .claude/settings*.json 是否带 hooks(实测只读 cwd,不向 git 根/父目录找):
# 有则交互确认——继续执行或切 disableAllHooks 模式。
# 用法:
#   runclaude.sh [claude args...]   启动(未安装时提示先跑 install)
#   runclaude.sh install            下载官方最新版并校验安装(macOS 走 installer;Windows 直接替换二进制)
set -u

# 防注入继承:实测 claude 的 Bun 运行时会执行 BUN_OPTIONS 里的 --preload
unset BUN_OPTIONS NODE_OPTIONS DYLD_INSERT_LIBRARIES

PY=$(command -v python3 || command -v python)

# 解析脚本自身真实路径:支持被符号链接/拷贝到 PATH(例如 ~/runclaude.sh)
SELF=$0
if readlink -f "$0" >/dev/null 2>&1; then
  SELF=$(readlink -f "$0")
elif [ -n "$PY" ]; then
  SELF=$("$PY" -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$0")
fi
ROOT=$(cd "$(dirname "$SELF")/.." 2>/dev/null && pwd)

# ---- 平台选择: 加载器 / 目标二进制 / 发布平台名 ------------------------------
case "$(uname -s)" in
  Darwin)
    PLATFORM=darwin-arm64
    BIN=claude
    CLAUDE=$HOME/.local/bin/claude
    LOADER_REL=target/release/mldr
    LOADER_NAME=mldr
    BUILD_HINT="cargo build --release(仓库根目录)"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    case "$(uname -m)" in
      x86_64|AMD64) ;;
      *) echo "peldr 目前仅支持 x64: $(uname -m)" >&2; exit 1 ;;
    esac
    PLATFORM=win32-x64
    BIN=claude.exe
    CLAUDE=$HOME/.local/bin/claude.exe
    LOADER_REL=peldr/target/release/peldr.exe
    LOADER_NAME=peldr.exe
    BUILD_HINT="cargo build --release(在 peldr/ 目录)"
    ;;
  *)
    echo "不支持的平台: $(uname -s)(本脚本支持 macOS/mldr 与 Windows Git Bash/peldr)" >&2
    exit 1
    ;;
esac

# ---- 定位加载器: RUNCLAUDE_LOADER > 脚本所在仓库 ------------------------------
LOADER=
for cand in "${RUNCLAUDE_LOADER:-}" "$ROOT/$LOADER_REL"; do
  if [ -n "$cand" ] && [ -f "$cand" ]; then
    LOADER=$cand
    break
  fi
done
if [ -z "$LOADER" ]; then
  echo "未找到加载器 $LOADER_NAME" >&2
  echo "  已查找: RUNCLAUDE_LOADER、$ROOT/$LOADER_REL" >&2
  echo "  请先构建或设置 RUNCLAUDE_LOADER:$BUILD_HINT" >&2
  exit 1
fi

STATUSLINE=$HOME/.claude/statusline-command.sh
BASE_URL=https://downloads.claude.ai/claude-code-releases

export DISABLE_AUTOUPDATER=1
export https_proxy=http://127.0.0.1:7899 http_proxy=http://127.0.0.1:7899
export HTTPS_PROXY=$https_proxy HTTP_PROXY=$http_proxy

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# 列出 $PWD/.claude 两个 settings 文件里配置的 hook 事件;无 hooks 时输出为空
list_dir_hooks() {
  "$PY" - "$PWD" <<'PYEOF'
import json, os, sys
for name in ("settings.json", "settings.local.json"):
    p = os.path.join(sys.argv[1], ".claude", name)
    try:
        with open(p) as fh:
            hooks = json.load(fh).get("hooks") or {}
    except (OSError, ValueError):
        continue
    events = [k for k, v in hooks.items() if v]
    if events:
        print("  " + p + ": " + ", ".join(events))
PYEOF
}

# 自带生成 settings,以 JSON 字符串形式传给 --settings(gen_settings strict 时叠加 disableAllHooks)
gen_settings() {
  "$PY" - "$STATUSLINE" "${1:-}" <<'PYEOF'
import json, os, sys
d = {
    "disableRemoteControl": True,
    "attribution": {"commit": "", "pr": ""},
}
# statusLine 软引用:脚本存在才注入,不硬依赖其他项目的产物
if os.path.isfile(sys.argv[1]):
    d["statusLine"] = {"type": "command", "command": "bash ~/.claude/statusline-command.sh"}
if len(sys.argv) > 2 and sys.argv[2] == "strict":
    d["disableAllHooks"] = True
print(json.dumps(d))
PYEOF
}

do_install() {
  # macOS:官方 installer 经 mldr 运行正常,沿用(会顺带写 PATH/rc);
  # Windows:官方更新器在手动映射下会踩堆损坏,改为"下载->校验->直接替换二进制"
  if [ -e "$CLAUDE" ] && [ "$PLATFORM" = darwin-arm64 ]; then
    echo "==> claude 已安装,经 $LOADER 调用其 install 更新..."
    "$LOADER" "$CLAUDE" install
    return $?
  fi

  echo "==> 查询最新版本..."
  version=$(curl -fsSL "$BASE_URL/latest") || { echo "查询失败(检查代理 $https_proxy)"; return 1; }
  echo "    版本: $version"

  dir=$HOME/.claude/downloads
  mkdir -p "$dir"
  bin=$dir/claude-$version-$PLATFORM
  [ "$BIN" = claude.exe ] && bin=$bin.exe

  if [ ! -f "$bin" ] && command -v zstd >/dev/null 2>&1; then
    echo "==> 下载 $version ($PLATFORM, zst)..."
    if curl -fsSL "$BASE_URL/$version/$PLATFORM/$BIN.zst" -o "$bin.zst" \
        && zstd -d -q -f -o "$bin" "$bin.zst"; then
      rm -f "$bin.zst"
    else
      rm -f "$bin.zst" "$bin"
    fi
  fi
  if [ ! -f "$bin" ]; then
    echo "==> 下载 $version ($PLATFORM)..."
    curl -fsSL "$BASE_URL/$version/$PLATFORM/$BIN" -o "$bin" || { echo "下载失败"; return 1; }
  fi

  echo "==> 校验 checksum..."
  want=$(curl -fsSL "$BASE_URL/$version/manifest.json" \
    | "$PY" -c "import json,sys; print(json.load(sys.stdin)['platforms']['$PLATFORM']['checksum'])") \
    || { echo "获取 manifest 失败"; return 1; }
  got=$(sha256 "$bin")
  if [ "$want" != "$got" ]; then
    echo "checksum 不匹配(期望 $want,实际 $got),删除损坏文件" >&2
    rm -f "$bin"
    return 1
  fi
  chmod +x "$bin"

  if [ "$PLATFORM" = darwin-arm64 ]; then
    echo "==> 经加载器执行 install..."
    "$LOADER" "$bin" install || { echo "install 失败"; return 1; }
  else
    echo "==> 安装到 $CLAUDE ..."
    mkdir -p "$(dirname "$CLAUDE")"
    [ -e "$CLAUDE" ] && cp -f "$CLAUDE" "$CLAUDE.bak"
    cp -f "$bin" "$CLAUDE" || { echo "复制失败"; return 1; }
    chmod +x "$CLAUDE"
  fi
  echo "==> 经加载器校验安装结果..."
  if ! "$LOADER" "$CLAUDE" --version; then
    if [ -e "$CLAUDE.bak" ]; then
      echo "校验失败,回滚" >&2
      cp -f "$CLAUDE.bak" "$CLAUDE"
    fi
    return 1
  fi
  echo "==> 安装/更新完成"
}

if [ "${1:-}" = "install" ]; then
  shift
  do_install
  exit $?
fi

if [ ! -e "$CLAUDE" ]; then
  echo "claude 未安装,请先运行: $0 install" >&2
  exit 1
fi

settings_arg=$(gen_settings) || exit 1
hook_summary=$(list_dir_hooks)
if [ -n "$hook_summary" ]; then
  echo "注意: 当前目录 settings 配置了 hooks,会拦截会话的输入输出:"
  echo "$hook_summary"
  if [ -t 0 ]; then
    printf "继续执行(保留 hooks)[c] / 进入 disableAllHooks 模式[d]? [c] "
    read -r ans
    case "$ans" in
      d|D)
        settings_arg=$(gen_settings strict) || exit 1
        echo "==> 已切换为 disableAllHooks 模式"
        ;;
    esac
  else
    echo "  非交互运行,继续执行;需要禁用请交互运行选择[d]" >&2
  fi
fi

exec "$LOADER" "$CLAUDE" \
  --settings "$settings_arg" \
  --setting-sources project,local \
  --dangerously-skip-permissions "$@"
