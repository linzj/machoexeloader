#!/usr/bin/env bash
# Build conprobe.exe (console-wait probe) with the same toolchain as pldr.
set -eu
cd "$(dirname "$0")"

winpath() { sed -e 's|^/\([a-zA-Z]\)/|\U\1:/|' -e 's|/|\\|g' <<<"$1"; }

VS_MSVC=''
for d in '/c/Program Files/Microsoft Visual Studio/2022/'*/VC/Tools/MSVC; do
    [ -d "$d" ] && { VS_MSVC=$d; break; }
done
MSVC_VER=${PELDR_MSVC_VER:-$(ls "$VS_MSVC" 2>/dev/null | sort -V | tail -1)}
SDK_ROOT='/c/Program Files (x86)/Windows Kits/10'
SDK_VER=${PELDR_SDK_VER:-$(ls "$SDK_ROOT/Include" 2>/dev/null | grep '^10\.' | sort -V | tail -1)}
MSVC="$(winpath "$VS_MSVC")\\$MSVC_VER"
SDK="$(winpath "$SDK_ROOT")"
export INCLUDE="$MSVC\\include;$SDK\\Include\\$SDK_VER\\ucrt;$SDK\\Include\\$SDK_VER\\um;$SDK\\Include\\$SDK_VER\\shared"
export LIB="$MSVC\\lib\\x64;$SDK\\Lib\\$SDK_VER\\ucrt\\x64;$SDK\\Lib\\$SDK_VER\\um\\x64"
CL="$VS_MSVC/$MSVC_VER/bin/HostX64/x64/cl.exe"

mkdir -p out
"$CL" //O2 //Fe:out\\conprobe.exe conprobe.c
echo "built: out/conprobe.exe"
