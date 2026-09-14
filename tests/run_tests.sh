#!/bin/bash
# Compares mldr-run output and exit codes against native execution.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --quiet
mkdir -p tests/out
CC=${CC:-clang}
CFLAGS="-g -O0"

$CC $CFLAGS -o tests/out/hello tests/targets/hello.c
$CC $CFLAGS -o tests/out/exitcode tests/targets/exitcode.c
$CC $CFLAGS -o tests/out/tls tests/targets/tls.c
$CC $CFLAGS -o tests/out/threads tests/targets/threads.c
$CC $CFLAGS -o tests/out/ctor tests/targets/ctor.c
# Classic LC_DYLD_INFO fixups instead of chained fixups.
$CC $CFLAGS -Wl,-no_fixup_chains -o tests/out/hello_classic tests/targets/hello.c
# Dependency chain: greettest -> @rpath/libgreet.dylib -> @loader_path/libsuffix.dylib
$CC $CFLAGS -dynamiclib -install_name @loader_path/libsuffix.dylib \
    -o tests/out/libsuffix.dylib tests/targets/suffix.c
$CC $CFLAGS -dynamiclib -install_name @rpath/libgreet.dylib \
    -o tests/out/libgreet.dylib tests/targets/greet.c \
    -L tests/out -lsuffix -Wl,-rpath,@loader_path
$CC $CFLAGS -o tests/out/greettest tests/targets/greettest.c \
    -L tests/out -lgreet -Wl,-rpath,@loader_path

pass=0
fail=0

run_case() {
    local name=$1
    shift
    local native_code mldr_code
    set +e
    ./tests/out/$name "$@" > tests/out/$name.native.out 2>/dev/null
    native_code=$?
    ./target/debug/mldr ./tests/out/$name "$@" > tests/out/$name.mldr.out 2>/dev/null
    mldr_code=$?
    set -e
    if [ "$native_code" -ne "$mldr_code" ]; then
        echo "FAIL $name: exit code native=$native_code mldr=$mldr_code"
        fail=$((fail + 1))
        return
    fi
    if ! diff -u tests/out/$name.native.out tests/out/$name.mldr.out > tests/out/$name.diff 2>&1; then
        echo "FAIL $name: stdout differs (see tests/out/$name.diff)"
        fail=$((fail + 1))
        return
    fi
    echo "PASS $name (exit $native_code)"
    pass=$((pass + 1))
}

run_case hello
run_case hello a b c
run_case exitcode 42
run_case exitcode 0
run_case tls
run_case threads
run_case ctor
run_case hello_classic
run_case greettest

# Claude Code native binary (207MB, Bun/JSC, 96k+ fixups, TLS).
CLAUDE=tmp/claude-code/node_modules/@anthropic-ai/claude-code-darwin-arm64/claude
if [ -f "$CLAUDE" ]; then
    # Load, map, fix up and bind everything without executing.
    if ./target/debug/mldr -e "$CLAUDE" >/dev/null 2>&1; then
        echo "PASS claude-load-only"
        pass=$((pass + 1))
    else
        echo "FAIL claude-load-only"
        fail=$((fail + 1))
    fi
    # Fully execute it. --version/--help are offline; executing the native
    # binary directly is blocked in this environment, so no native diff.
    if ./target/debug/mldr "$CLAUDE" --version 2>/dev/null | grep -q "Claude Code"; then
        echo "PASS claude-exec-version"
        pass=$((pass + 1))
    else
        echo "FAIL claude-exec-version"
        fail=$((fail + 1))
    fi
fi

echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
