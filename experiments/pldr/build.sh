#!/usr/bin/env bash
# Build pldr: the ntdll-only pure loader skeleton.
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
[ -n "$MSVC_VER" ] && [ -n "$SDK_VER" ] || { echo "toolchain not found"; exit 1; }
MSVC="$(winpath "$VS_MSVC")\\$MSVC_VER"
SDK="$(winpath "$SDK_ROOT")"
export INCLUDE="$MSVC\\include;$SDK\\Include\\$SDK_VER\\ucrt;$SDK\\Include\\$SDK_VER\\um;$SDK\\Include\\$SDK_VER\\shared"
export LIB="$MSVC\\lib\\x64;$SDK\\Lib\\$SDK_VER\\ucrt\\x64;$SDK\\Lib\\$SDK_VER\\um\\x64"
CL="$VS_MSVC/$MSVC_VER/bin/HostX64/x64/cl.exe"
LINK="$VS_MSVC/$MSVC_VER/bin/HostX64/x64/link.exe"

mkdir -p out
(
    cd out
    MSYS_NO_PATHCONV=1 "$CL" /nologo /Od /GS- /c ../main.c 2>&1 || exit 1
    MSYS_NO_PATHCONV=1 "$LINK" /NOLOGO /NODEFAULTLIB /ENTRY:pldr_main \
        /SUBSYSTEM:CONSOLE /STACK:16777216 /OUT:pldr.exe main.obj ntdll.lib || exit 1
)
echo "built: out/pldr.exe"
