"""Compile one source file with the game's GCC (C with arm-elf-gcc, C++ with arm-elf-g++) and give its symbols the
original's names (tools/names.py), without a shell parsing paths or flags."""

import argparse
import subprocess
import sys
from pathlib import Path

COMPILE_SECONDS = 300
# what every file is built with, whatever its flags: one section per function (tools/delink.py cuts the original
# that way), and the project's headers (the compiler brings only its own: stddef.h, stdarg.h, limits.h, float.h)
ALWAYS = ["-c", "-ffunction-sections", "-Iinclude"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gcc", required=True, help="the compiler's folder (holds bin/arm-elf-gcc)")
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("flags", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    flags = args.flags[1:] if args.flags[:1] == ["--"] else args.flags
    cxx = Path(args.source).suffix.lower() in (".cpp", ".cc", ".cxx")
    driver = Path(args.gcc) / "bin" / ("arm-elf-g++" if cxx else "arm-elf-gcc")
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([str(driver), *ALWAYS, *flags, "-o", args.output, args.source], timeout=COMPILE_SECONDS)
    if result.returncode:
        return result.returncode
    return subprocess.run([sys.executable, str(Path(__file__).with_name("names.py")), args.config, args.output],
                          timeout=COMPILE_SECONDS).returncode


if __name__ == "__main__":
    sys.exit(main())
