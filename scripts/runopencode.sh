#!/bin/sh
# 经 peldr 用户态加载器启动 opencode2 原生二进制(不经过 CreateProcess/ntdll Ldr)。
# 用法:
#   runopencode.sh [opencode args...]   启动(默认带 -v,详细日志落 $HOME/peldr-oc.log)
#   RUNOPENCODE_VERBOSE=0 runopencode.sh   关闭 -v 详细日志
#   RUNOPENCODE_TARGET=<path> runopencode.sh   换目标二进制
#   RUNOPENCODE_LOADER=<path> runopencode.sh   换加载器
set -u

# 防注入继承(与 runclaude.sh 同一套)
unset BUN_OPTIONS NODE_OPTIONS DYLD_INSERT_LIBRARIES

# 解析脚本真实路径(支持被符号链接到 ~)
SELF=$0
if readlink -f "$0" >/dev/null 2>&1; then
  SELF=$(readlink -f "$0")
fi
ROOT=$(cd "$(dirname "$SELF")/.." 2>/dev/null && pwd)

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    case "$(uname -m)" in
      x86_64|AMD64) ;;
      *) echo "peldr 目前仅支持 x64: $(uname -m)" >&2; exit 1 ;;
    esac
    LOADER_REL=peldr/target/release/peldr.exe
    LOADER_NAME=peldr.exe
    OC2=${RUNOPENCODE_TARGET:-$HOME/.opencode/bin/opencode2.exe}
    ;;
  *)
    echo "runopencode.sh 目前仅支持 Windows(peldr): $(uname -s)" >&2
    exit 1
    ;;
esac

case "${RUNOPENCODE_VERBOSE:-1}" in
  0) LOADER_FLAGS= ;;
  *) LOADER_FLAGS=-v ;;
esac
export PELDR_LOG=${PELDR_LOG:-$HOME/peldr-oc.log}
rm -f "$PELDR_LOG" 2>/dev/null

LOADER=
for cand in "${RUNOPENCODE_LOADER:-}" "$ROOT/$LOADER_REL"; do
  if [ -n "$cand" ] && [ -f "$cand" ]; then
    LOADER=$cand
    break
  fi
done
if [ -z "$LOADER" ]; then
  echo "未找到加载器 $LOADER_NAME" >&2
  echo "  已查找: RUNOPENCODE_LOADER、$ROOT/$LOADER_REL" >&2
  echo "  请先构建: cargo build --release(在 peldr/ 目录)" >&2
  exit 1
fi
if [ ! -f "$OC2" ]; then
  echo "未找到 opencode2 二进制: $OC2" >&2
  exit 1
fi

export https_proxy=http://127.0.0.1:7899 http_proxy=http://127.0.0.1:7899
export HTTPS_PROXY=$https_proxy HTTP_PROXY=$http_proxy
export DISABLE_AUTOUPDATER=1

# 防呆: peldr 的 -v 由本脚本自动加(默认开), 不需要手动传;
# 若手动传 -v, 它会透传给 opencode2 —— 那是"查版本"旗标, 会打印版本后立即退出。
if [ "$#" -eq 1 ] && [ "$1" = "-v" ]; then
  echo "提示: 单个 -v 会被 opencode2 当作版本查询(打印版本后退出)。" >&2
  echo "      要启动 TUI 请直接运行: $0(不加参数);" >&2
  echo "      详细日志默认已开, 关闭: RUNOPENCODE_VERBOSE=0 $0" >&2
fi

echo "==> peldr $LOADER_FLAGS $OC2 $*"
echo "==> 日志: $PELDR_LOG"
"$LOADER" $LOADER_FLAGS "$OC2" "$@"
rc=$?
echo ""
echo "==> opencode2 已退出 rc=$rc (0x$(printf '%x' "$rc" 2>/dev/null || echo '?'))"
echo "==> 日志保留在 $PELDR_LOG(窗口别关,发我 rc 和日志)"
exit "$rc"
