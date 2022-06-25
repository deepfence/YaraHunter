#!/bin/sh

set -eu

readonly prefix=$1

case $prefix in
    *x86_64*)
	sed -i \
	    -e 's/^-dynamic-linker/-m elf_x86_64 &/' \
	    $prefix/lib/musl-gcc.specs
	cat >> $prefix/lib/musl-gcc.specs <<EOF
*multilib:
64:../lib64:x86_64-linux-gnu m64;

*multilib_defaults:
m64

*asm:
--64

*cc1_cpu:
-m64
EOF
	;;
    *i386*)
	sed -i \
	    -e 's/^-dynamic-linker/-m elf_i386 &/' \
	    $prefix/lib/musl-gcc.specs
	cat >> $prefix/lib/musl-gcc.specs <<EOF
*multilib:
32:../lib32:i386-linux-gnu m32;

*multilib_defaults:
m32

*asm:
--32

*cc1_cpu:
-m32
EOF
	;;
    default)
	echo "Could not guess architecture from prefix $prefix" >&2;
	exit 1 ;;
esac       

# On Debian/stretch x86_64 can't build executables without these
# options, see <https://bugs.debian.org/847776>. However, it seems that 
if [ -e /usr/share/dpkg/no-pie-link.specs ]; then
    sed -i \
	-e 's,-specs ,-specs /usr/share/dpkg/no-pie-link.specs &,' \
	$prefix/bin/musl-gcc
fi
if [ -e /usr/share/dpkg/no-pie-compile.specs ]; then
    sed -i \
	-e 's,-specs ,-specs /usr/share/dpkg/no-pie-compile.specs &,' \
	$prefix/bin/musl-gcc
fi
