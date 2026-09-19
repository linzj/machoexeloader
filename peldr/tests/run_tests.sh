#!/usr/bin/env bash
# peldr test suite: every target is run natively and through peldr with the
# same command line; stdout and exit codes must match.
set -u
cd "$(dirname "$0")/.."

winpath() { sed -e 's|^/\([a-zA-Z]\)/|\U\1:/|' -e 's|/|\\|g' <<<"$1"; }

# Toolchain: newest installed VS2022 MSVC toolset + Windows SDK (any edition).
# Override with PELDR_MSVC_VER / PELDR_SDK_VER when detection picks wrong.
VS_MSVC=''
for d in '/c/Program Files/Microsoft Visual Studio/2022/'*/VC/Tools/MSVC; do
    [ -d "$d" ] && { VS_MSVC=$d; break; }
done
MSVC_VER=${PELDR_MSVC_VER:-$(ls "$VS_MSVC" 2>/dev/null | sort -V | tail -1)}
SDK_ROOT='/c/Program Files (x86)/Windows Kits/10'
SDK_VER=${PELDR_SDK_VER:-$(ls "$SDK_ROOT/Include" 2>/dev/null | grep '^10\.' | sort -V | tail -1)}
if [ -z "$MSVC_VER" ] || [ -z "$SDK_VER" ]; then
    echo "MSVC toolset or Windows SDK not found; set PELDR_MSVC_VER / PELDR_SDK_VER"
    exit 1
fi
MSVC="$(winpath "$VS_MSVC")\\$MSVC_VER"
SDK="$(winpath "$SDK_ROOT")"
export INCLUDE="$MSVC\\include;$SDK\\Include\\$SDK_VER\\ucrt;$SDK\\Include\\$SDK_VER\\um;$SDK\\Include\\$SDK_VER\\shared"
export LIB="$MSVC\\lib\\x64;$SDK\\Lib\\$SDK_VER\\ucrt\\x64;$SDK\\Lib\\$SDK_VER\\um\\x64"
CL="$VS_MSVC/$MSVC_VER/bin/HostX64/x64/cl.exe"
PELDR=./target/debug/peldr.exe
export HTTPS_PROXY=http://127.0.0.1:7899
export HTTP_PROXY=http://127.0.0.1:7899

pass=0
fail=0

cargo build --quiet || { echo "cargo build failed"; exit 1; }

mkdir -p tests/out
cc() { MSYS_NO_PATHCONV=1 "$CL" /nologo /Od "$@" 2>&1; }
(
    cd tests/out || exit 1
    cc ../targets/hello.c || exit 1
    cc ../targets/exitcode.c || exit 1
    cc ../targets/ctor.c || exit 1
    cc ../targets/tls.c || exit 1
    cc ../targets/threads.c || exit 1
    cc ../targets/waiter.c || exit 1
    cc ../targets/exitthread.c ntdll.lib || exit 1
    cc ../targets/modname.c || exit 1
    cc -LD ../targets/suffix.c || exit 1
    cc -LD ../targets/greet.c suffix.lib || exit 1
    cc ../targets/greettest.c greet.lib || exit 1
    cc ../targets/greettest_delay.c greet.lib delayimp.lib /link /DELAYLOAD:greet.dll || exit 1
    cc -LD ../targets/tlsdll.c || exit 1
    cc ../targets/tlsdlltest.c || exit 1
) || { echo "target build failed"; exit 1; }

# Run one case natively and through peldr with identical argument strings.
run_case() {
    local name=$1
    shift
    local argstr=""
    for a in "$@"; do argstr="$argstr \"$a\""; done
    local nc pc
    set +e
    cmd //c "tests\\out\\$name.exe$argstr" > tests/out/$name.native.out 2>/dev/null
    nc=$?
    cmd //c "$PELDR_WIN tests\\out\\$name.exe$argstr" > tests/out/$name.peldr.out 2>/dev/null
    pc=$?
    set -e
    if [ "$nc" -ne "$pc" ]; then
        echo "FAIL $name: exit code native=$nc peldr=$pc"
        fail=$((fail + 1))
        return
    fi
    if ! diff -u tests/out/$name.native.out tests/out/$name.peldr.out > tests/out/$name.diff 2>&1; then
        echo "FAIL $name: stdout differs (see tests/out/$name.diff)"
        fail=$((fail + 1))
        return
    fi
    echo "PASS $name (exit $nc)"
    pass=$((pass + 1))
}

PELDR_WIN='target\debug\peldr.exe'

run_case hello
run_case hello a b c
run_case hello "a b" c
run_case exitcode 42
run_case exitcode 0
run_case ctor
run_case tls
run_case threads
run_case waiter
run_case exitthread
run_case modname
run_case greettest
run_case greettest_delay
run_case tlsdlltest

# Forced relocation: same outputs, all images loaded away from ImageBase.
PELDR_WIN='target\debug\peldr.exe -r'
run_case greettest
run_case hello a b
PELDR_WIN='target\debug\peldr.exe'

# Real-world binary: Claude Code native (win32-x64). Not committed; skipped
# when missing. See README for the download command.
CLAUDE=tmp/claude-code/node_modules/@anthropic-ai/claude-code-win32-x64/claude.exe
if [ -f "$CLAUDE" ]; then
    if $PELDR -e "$CLAUDE" >/dev/null 2>&1; then
        echo "PASS claude-load-only"
        pass=$((pass + 1))
    else
        echo "FAIL claude-load-only"
        fail=$((fail + 1))
    fi
    if $PELDR "$CLAUDE" --version 2>/dev/null | grep -q "Claude Code"; then
        echo "PASS claude-exec-version"
        pass=$((pass + 1))
    else
        echo "FAIL claude-exec-version"
        fail=$((fail + 1))
    fi
    if $PELDR "$CLAUDE" --help 2>/dev/null | grep -q "Usage: claude"; then
        echo "PASS claude-exec-help"
        pass=$((pass + 1))
    else
        echo "FAIL claude-exec-help"
        fail=$((fail + 1))
    fi
    if $PELDR -r "$CLAUDE" --version 2>/dev/null | grep -q "Claude Code"; then
        echo "PASS claude-exec-version-rebased"
        pass=$((pass + 1))
    else
        echo "FAIL claude-exec-version-rebased"
        fail=$((fail + 1))
    fi
else
    echo "SKIP claude-*: $CLAUDE not found"
    echo "      npm install --prefix tmp/claude-code @anthropic-ai/claude-code-win32-x64@2.1.270"
fi

echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
