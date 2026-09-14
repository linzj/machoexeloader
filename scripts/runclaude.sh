#!/bin/sh
# 经 mldr 用户态加载 claude 原生二进制启动
# 环境/flags 对齐 ~/.local/bin/claude-node:
#   DISABLE_AUTOUPDATER=1、本机代理、--settings nohooks.json、
#   --setting-sources project,local(排除 user settings
#   注入的钩子都挂在 user settings 里)、--dangerously-skip-permissions;
#   不挂任何 BUN_OPTIONS preload 钩子。
# 启动前检测 cwd 的 .claude/settings*.json 是否带 hooks(实测只读 cwd,不向 git 根/父目录找):
# 有则交互确认——继续执行或切 disableAllHooks 模式。
# 用法:
#   runclaude.sh [claude args...]   启动(未安装时提示先跑 install)
#   runclaude.sh install            已安装则经 mldr 直接执行 claude install 更新;未安装则下载校验后安装
set -u

# 防注入继承:实测 claude 的 Bun 运行时会执行 BUN_OPTIONS 里的 --preload
unset BUN_OPTIONS NODE_OPTIONS DYLD_INSERT_LIBRARIES

MLDR=$HOME/src/machoexeloader/target/release/mldr
CLAUDE=$HOME/.local/bin/claude
SETTINGS=$HOME/.local/lib/claude-code-bun/nohooks.json
BASE_URL=https://downloads.claude.ai/claude-code-releases
PLATFORM=darwin-arm64

export DISABLE_AUTOUPDATER=1
export https_proxy=http://127.0.0.1:7899 http_proxy=http://127.0.0.1:7899
export HTTPS_PROXY=$https_proxy HTTP_PROXY=$http_proxy

sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

# 列出 $PWD/.claude 两个 settings 文件里配置的 hook 事件;无 hooks 时输出为空
list_dir_hooks() {
  python3 - "$PWD" <<'PYEOF'
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

# nohooks.json 基础上追加 disableAllHooks,以 JSON 字符串形式传给 --settings
strict_settings() {
  python3 - "$SETTINGS" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as fh:
    d = json.load(fh)
d["disableAllHooks"] = True
print(json.dumps(d))
PYEOF
}

do_install() {
  if [ -e "$CLAUDE" ]; then
    echo "==> claude 已安装,经 mldr 调用其 install 更新..."
    "$MLDR" "$CLAUDE" install
    return $?
  fi

  echo "==> 查询最新版本..."
  version=$(curl -fsSL "$BASE_URL/latest") || { echo "查询失败(检查代理 $https_proxy)"; return 1; }
  echo "    版本: $version"

  dir=$HOME/.claude/downloads
  mkdir -p "$dir"
  bin=$dir/claude-$version-$PLATFORM

  if [ ! -f "$bin" ] && command -v zstd >/dev/null 2>&1; then
    echo "==> 下载 $version ($PLATFORM, zst)..."
    if curl -fsSL "$BASE_URL/$version/$PLATFORM/claude.zst" -o "$bin.zst" \
        && zstd -d -q -f -o "$bin" "$bin.zst"; then
      rm -f "$bin.zst"
    else
      rm -f "$bin.zst" "$bin"
    fi
  fi
  if [ ! -f "$bin" ]; then
    echo "==> 下载 $version ($PLATFORM)..."
    curl -fsSL "$BASE_URL/$version/$PLATFORM/claude" -o "$bin" || { echo "下载失败"; return 1; }
  fi

  echo "==> 校验 checksum..."
  want=$(curl -fsSL "$BASE_URL/$version/manifest.json" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['platforms']['$PLATFORM']['checksum'])") \
    || { echo "获取 manifest 失败"; return 1; }
  got=$(sha256 "$bin")
  if [ "$want" != "$got" ]; then
    echo "checksum 不匹配(期望 $want,实际 $got),删除损坏文件" >&2
    rm -f "$bin"
    return 1
  fi
  chmod +x "$bin"

  echo "==> 经 mldr 执行 install..."
  "$MLDR" "$bin" install || { echo "install 失败"; return 1; }
  echo "==> 校验安装结果..."
  "$MLDR" "$CLAUDE" --version || return 1
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

settings_arg=$SETTINGS
hook_summary=$(list_dir_hooks)
if [ -n "$hook_summary" ]; then
  echo "注意: 当前目录 settings 配置了 hooks,会拦截会话的输入输出:"
  echo "$hook_summary"
  if [ -t 0 ]; then
    printf "继续执行(保留 hooks)[c] / 进入 disableAllHooks 模式[d]? [c] "
    read -r ans
    case "$ans" in
      d|D)
        settings_arg=$(strict_settings) || exit 1
        echo "==> 已切换为 disableAllHooks 模式"
        ;;
    esac
  else
    echo "  非交互运行,继续执行;需要禁用请交互运行选择[d]" >&2
  fi
fi

exec "$MLDR" "$CLAUDE" \
  --settings "$settings_arg" \
  --setting-sources project,local \
  --dangerously-skip-permissions "$@"
