#!/usr/bin/env python3
"""Regenerate dlls/ntdll/unix/win10_19045_syscalls.h from the public
Windows syscall table (j00ru/windows-syscalls, x64/csv/nt.csv, column
"Windows 10 (22H2)"; builds 19041..19045 are identical)."""

import csv, sys, os

csv_path = os.path.join(os.path.dirname(__file__), "nt_x64.csv")
out_path = os.path.join(os.path.dirname(__file__), "../../dlls/ntdll/unix/win10_19045_syscalls.h")
column = "Windows 10 (22H2)"

def main():
    rows = list(csv.reader(open(csv_path)))
    header = rows[0]
    col = header.index(column)
    entries = []
    for row in rows[1:]:
        value = row[col].strip()
        if value:
            entries.append((int(value, 16), row[0]))
    entries.sort()
    out = []
    out.append("""/*
 * Windows 10 build 19045 (x86-64) NT syscall numbers
 *
 * Generated from the public Windows syscall table published by
 * Mateusz Jurczyk (j00ru/windows-syscalls, x64/csv/nt.csv, column
 * "Windows 10 (22H2)"; builds 19041..19045 are identical).
 * Regenerate with tools/gen_win10_19045_syscalls.py.
 *
 * The unix side maps a Windows syscall number to the wine syscall id
 * of the ntdll stub exporting the same function, so that raw syscall
 * instructions executed by native code are serviced like on Windows.
 */

#ifndef __NTDLL_WIN10_SYSCALLS_H
#define __NTDLL_WIN10_SYSCALLS_H

""")
    out.append("#define WIN10_19045_SYSCALL_COUNT %#06x\n\n" % (entries[-1][0] + 1))
    out.append("static const struct windows_syscall\n{\n    unsigned int nr;\n    const char *name;\n}\n")
    out.append("windows_syscalls_WIN10_19045[] =\n{\n")
    for nr, name in entries:
        out.append('    { %#06x, "%s" },\n' % (nr, name))
    out.append("};\n\n#endif /* __NTDLL_WIN10_SYSCALLS_H */\n")
    open(out_path, "w").write("".join(out))
    print("%d entries -> %s" % (len(entries), out_path))

if __name__ == "__main__":
    main()
