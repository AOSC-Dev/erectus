# SPDX-FileCopyrightText: Copyright 2025 Anthon Open Source Community
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import csv
import sys


varname = os.environ.get("VAR_NAME", "errno_lut")
# This script generates a C header file containing a lookup table for errno values.
table = []
output = ""
with open("errno-table.csv", "r") as f:
    reader = csv.reader(f.readlines())
    for line in reader:
        if line[0] == "name":
            continue
        name, ncall, ocall = line
        ncall_int = int(ncall or -1)
        ocall_int = int(ocall or -1)
        ch = ocall_int - ncall_int
        if ncall_int == -1:
            continue
        if ocall_int == -1:
            ch = 0
        table.append((name, ncall_int, ch))

sorted_table = sorted(table, key=lambda x: x[1])
if varname.endswith("_lut"):
    output += f"static const char {varname}[] = {{"
    for name, ncall, ch in sorted_table:
        if ch < -127 or ch > 128:
            output += f"/* Skipping large change for {name} */"
            ch = 0
        output += f"    /* {name} */ {ch},"
    output += "};"
else:
    # generate switch statement
    output += f"static const inline int {varname}(const int errno) {{"
    output += "    switch (errno) {"
    for name, ncall, ch in sorted_table:
        if ch == 0:
            continue
        output += f"    case {ncall}: return {ncall} + {ch}; // {name}"
    output += "    default: return errno;"
    output += "}\n}"


if len(sys.argv) > 1:
    with open(sys.argv[1], "w") as f:
        f.write(output)
else:
    print(output)
