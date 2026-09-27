#!/usr/bin/env python3
"""Run Python CI fixtures and refuse an empty, skipped or failed test selection."""
import re
import subprocess
import sys

def passed(code, output):
    counts = re.findall(r'^Ran ([0-9]+) tests? in ', output, re.M)
    return code == 0 and len(counts) == 1 and int(counts[0]) > 0 and re.search(r'^OK$', output, re.M) is not None

def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: run-ci-tests.py DIRECTORY PATTERN')
    result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', sys.argv[1], '-p', sys.argv[2]],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(result.stdout, end='')
    if not passed(result.returncode, result.stdout):
        raise SystemExit('CI fixtures must execute nonempty, passing, unskipped tests')

if __name__ == '__main__': main()
