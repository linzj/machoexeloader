#!/usr/bin/env bash
# elldr test suite: every target runs natively and through elldr, then stdout
# and exit codes are compared. The claude-* cases need the Claude Code native
# linux-x64 binary and are skipped when it is absent.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --quiet
mkdir -p tests/out

CC=${CC:-cc}
CFLAGS="-no-pie -O0 -g"
ELDDR=./target/debug/elldr

$CC $CFLAGS -o tests/out/hello        tests/targets/hello.c
$CC $CFLAGS -o tests/out/exitcode     tests/targets/exitcode.c
$CC $CFLAGS -o tests/out/tls          tests/targets/tls.c
$CC $CFLAGS -o tests/out/threads      tests/targets/threads.c -pthread
$CC $CFLAGS -o tests/out/ctor         tests/targets/ctor.c
$CC $CFLAGS -o tests/out/ifunc        tests/targets/ifunc.c
$CC $CFLAGS -o tests/out/reloc        tests/targets/reloc.c
$CC $CFLAGS -o tests/out/phdr         tests/targets/phdr.c
$CC $CFLAGS -o tests/out/fork         tests/targets/fork.c

pass=0
fail=0

run_case() {
    local name=$1
    shift
    local rc_n rc_e
    set +e
    "./tests/out/$name" "$@" > "tests/out/$name.native.out" 2>&1
    rc_n=$?
    timeout 60 "$ELDDR" "./tests/out/$name" "$@" > "tests/out/$name.elldr.out" 2>&1
    rc_e=$?
    set -e
    if [ "$rc_n" != "$rc_e" ]; then
        echo "FAIL $name: exit code native=$rc_n elldr=$rc_e"
        fail=$((fail + 1))
        return
    fi
    if ! diff -u "tests/out/$name.native.out" "tests/out/$name.elldr.out" \
        > "tests/out/$name.diff" 2>&1; then
        echo "FAIL $name: stdout differs (see tests/out/$name.diff)"
        fail=$((fail + 1))
        return
    fi
    echo "PASS $name (rc=$rc_n)"
    pass=$((pass + 1))
}

run_case hello
run_case hello a b c
run_case hello "a b" c
run_case exitcode 42
run_case exitcode 0
run_case tls
run_case threads
run_case ctor
run_case ifunc
run_case reloc
run_case phdr
run_case fork

# ---- claude-*: the real target (Bun single-file executable) ----------------
CLAUDE="${CLAUDE_BIN:-}"
if [ -z "$CLAUDE" ]; then
    if [ -x tmp/claude-code/node_modules/@anthropic-ai/claude-code-linux-x64/claude ]; then
        CLAUDE=tmp/claude-code/node_modules/@anthropic-ai/claude-code-linux-x64/claude
    elif [ -d "$HOME/.local/share/claude/versions" ]; then
        latest=$(ls -1 "$HOME/.local/share/claude/versions" 2>/dev/null | sort -V | tail -1)
        [ -n "$latest" ] && CLAUDE="$HOME/.local/share/claude/versions/$latest"
    fi
fi

if [ -z "$CLAUDE" ] || [ ! -x "$CLAUDE" ]; then
    echo "SKIP claude-*: native binary not found"
    echo "  install with: npm install --prefix tmp/claude-code @anthropic-ai/claude-code-linux-x64@latest"
    echo "  and point CLAUDE_BIN at node_modules/@anthropic-ai/claude-code-linux-x64/claude"
else
    echo "claude target: $CLAUDE"
    set +e
    timeout 120 "$ELDDR" -e "$CLAUDE" > /dev/null 2>&1
    rc=$?
    set -e
    if [ "$rc" = 0 ]; then
        echo "PASS claude-load-only"
        pass=$((pass + 1))
    else
        echo "FAIL claude-load-only (rc=$rc)"
        fail=$((fail + 1))
    fi

    for cmdline in "--version" "--help"; do
        case_name="claude-exec${cmdline#-}"
        set +e
        timeout 60 "$CLAUDE" $cmdline > tests/out/claude.native.out 2>/dev/null
        rc_n=$?
        timeout 60 "$ELDDR" "$CLAUDE" $cmdline > tests/out/claude.elldr.out 2>/dev/null
        rc_e=$?
        set -e
        if [ "$rc_n" = "$rc_e" ] && diff -q tests/out/claude.native.out tests/out/claude.elldr.out > /dev/null; then
            echo "PASS $case_name (rc=$rc_n)"
            pass=$((pass + 1))
        else
            echo "FAIL $case_name: native rc=$rc_n elldr rc=$rc_e"
            fail=$((fail + 1))
        fi
    done
fi

echo
echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
