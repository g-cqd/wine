#!/bin/bash
# Rebuild and run all four risk probes; outputs go to out/*.txt. Needs the Developer ID identity and the winehost profile (see sign_app.sh).
set -u
cd "$(dirname "$0")"; W=/tmp/wa64p; mkdir -p $W out
clang -arch arm64 -o $W/launch launch.c
mk() { local n=$1 src=$2; shift 2; clang -arch arm64 -O1 -mmacos-version-min=26.4 -o $W/$n $src "$@" 2>&1 | grep -v warning; }
# (a) x18
mk x18 x18.c; mk x18b x18b.c
./sign_app.sh $W/x18_noent.app $W/x18 >/dev/null; ./sign_app.sh $W/x18_ent.app $W/x18 com.apple.security.custom-x18-abi-toggle >/dev/null
./sign_app.sh $W/x18b_noent.app $W/x18b >/dev/null; ./sign_app.sh $W/x18b_ent.app $W/x18b com.apple.security.custom-x18-abi-toggle >/dev/null
cp $W/x18b $W/x18b_adhoc; codesign -f -s - $W/x18b_adhoc 2>/dev/null
{ echo "### ad-hoc, no entitlements, plain (x18 API without cross-arch entitlement)"; $W/x18b_adhoc; echo "rc=$?";
  for v in x18_noent x18_ent; do for m in plain 4k; do echo "### $v $m (x18 treated as ordinary register, no os_set_custom_x18_abi_enabled)"; $W/launch $m $W/$v.app/Contents/MacOS/x18; done; done
  for v in x18b_noent x18b_ent; do for m in plain 4k; do echo "### $v $m (os_set_custom_x18_abi_enabled(true))"; $W/launch $m $W/$v.app/Contents/MacOS/x18b; done; done; } > out/a_x18.txt 2>&1
# (b) executable mappings
mk mapexec mapexec.c
./sign_app.sh $W/mx_rt.app $W/mapexec >/dev/null; ./sign_app.sh $W/mx_rt_aue.app $W/mapexec com.apple.security.cs.allow-unsigned-executable-memory >/dev/null
./sign_app.sh $W/mx_dep.app $W/mapexec com.apple.security.cs.disable-executable-page-protection com.apple.security.cs.allow-unsigned-executable-memory >/dev/null
NORUNTIME=1 ./sign_app.sh $W/mx_nort.app $W/mapexec >/dev/null
for v in mx_rt mx_rt_aue mx_dep mx_nort; do echo "### $v (4k)"; $W/launch 4k $W/$v.app/Contents/MacOS/mapexec; done > out/b_mapexec.txt 2>&1
# (c) spawn / exec / 4K inheritance
mk spawn4k spawn4k.c; ./sign_app.sh $W/s4k.app $W/spawn4k >/dev/null; S=$W/s4k.app/Contents/MacOS/spawn4k
{ for m in report exec_attr exec_plain execve spawn_attr spawn_plain forkexec sys_plain sys_attr exec_sys; do echo "### start 4K, mode $m"; $W/launch 4k $S $m; done
  echo "### start 16K, mode exec_attr"; $W/launch plain $S exec_attr; echo "### start 16K, mode spawn_attr"; $W/launch plain $S spawn_attr; } > out/c_spawn.txt 2>&1
# (d) low reserve
for v in default emul emul_pz10000 emul_pz1000; do
  case $v in default) fl="";; emul) fl="-Wl,-x86_64_layout_emulation";; emul_pz10000) fl="-Wl,-x86_64_layout_emulation -Wl,-pagezero_size,0x10000";; emul_pz1000) fl="-Wl,-x86_64_layout_emulation -Wl,-pagezero_size,0x1000 -Wl,-segalign,0x1000";; esac
  mk lowres_$v lowres.c $fl; ./sign_app.sh $W/lr_$v.app $W/lowres_$v >/dev/null
  echo "### $v (4k)"; $W/launch 4k $W/lr_$v.app/Contents/MacOS/lowres_$v
done > out/d_lowres.txt 2>&1
echo done
