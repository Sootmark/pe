#!/bin/sh
# Builds sample.dll with mingw-w64 (Debian 13's gcc-mingw-w64-x86-64 and
# binutils-mingw-w64-x86-64, GNU ld 2.44), with fixed time stamps, then
# finish.py fills in what GNU ld leaves out. Run from this directory.
set -eu
export SOURCE_DATE_EPOCH=1700000000
here=$(pwd)
work=$(mktemp -d)
cd "$work"
x86_64-w64-mingw32-dlltool -d "$here/helper.def" -l libhelper.a
x86_64-w64-mingw32-dlltool -d "$here/user32.def" -y libuser32delay.a
x86_64-w64-mingw32-windres "$here/sample.rc" -O coff -o sample.res
x86_64-w64-mingw32-gcc -O1 -shared -nostartfiles -e DllMain -o sample.dll \
    "$here/sample.c" "$here/sample.def" sample.res \
    -L. -lhelper -luser32delay -lkernel32 \
    -Wl,--build-id -Wl,--pdb=sample -Wl,-Map=sample.map -s
address() { awk -v name="$1" '$2 == name { print $1 }' sample.map; }
python3 -I "$here/finish.py" sample.dll \
    "$(address __DELAY_IMPORT_DESCRIPTOR_libuser32delay_a)" "$(address _load_config_used)"
cp sample.dll "$here/sample.dll"
cd "$here"
rm -r "$work"
