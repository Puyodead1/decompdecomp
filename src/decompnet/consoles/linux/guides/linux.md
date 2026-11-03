# Matching GCC 2.95 on Linux (32-bit x86 programs, 2000-2002)

The program's own compiler is Slackware 8.0's GCC 2.95.3, usually `-O2` (the project's settings say; search_flags
tries `-O1`, `-O3` and others on a function). C, cdecl: arguments pushed right to left, the caller takes them off.

What the compiler writes, never the C
- The frame: `push ebp; mov ebp, esp; sub esp, N`, then `push edi; push esi; push ebx` for the callee-saved
  registers it uses; the end is `lea esp, [ebp-N]; pop ebx; pop esi; pop edi; leave; ret` (or `mov esp, ebp`). No
  ebp frame at all means `-fomit-frame-pointer`: ask search_flags.
- The stack kept 16-byte aligned around calls: `add esp, -0xc` (or `sub esp, 8`) before an argument's push, and
  `add esp, 0x10` after the call. It follows from how many arguments each call has: get the calls right and it
  comes out the same.
- Loop alignment: `.p2align 4,,7` pads a loop's start with `nop`, `lea esi, [esi]` or `lea esi, [esi+0]` (up to 7
  bytes). The padding depends on where the function sits; the judge compiles your function at its game address
  modulo 16, so the padding comes out as the game's when the code before it is the same. Never write it.

Reading the code for the C
- A parameter's real type: the debug information (the brief's prototype) gives a short or char parameter its
  promoted type, `int`. `movsx`/`cwde`/`movzx` on it right at the start (`mov eax, [ebp+8]; dec eax; cwde`) says
  it was `short` (or `unsigned short`, `char`): write the narrow type.
- `char` is signed on x86 Linux: `movsx` loads a plain `char`, `movzx` an `unsigned char`.
- switch: dense cases become `jmp [eax*4 + table]` with the table in .rodata; the judge places your table where the
  program keeps it. The cases' values and order must be the game's.
- Floats are x87: `fld dword` a float, `fld qword` a double. A float argument without a prototype is passed as a
  double: declare the callee.
- Library calls go through the PLT (`call printf`). glibc 2.2.3's own headers come with the compiler: your C may
  `#include <stdio.h>`, `<string.h>`, `<math.h>` and the like, as the game's files did (the shared header may
  already declare what you need; where an include clashes with it, declare only what the function uses).
- What glibc's headers inline is the game's C, not assembly: `out dx, al` / `in al, dx` are `<sys/io.h>`'s
  `outb(value, port)` / `inb(port)`; a bare `fsqrt`, `fsin` or `frndint` where the call to `sqrt`, `sin` or `rint`
  would be is `<math.h>`'s inline under `-ffast-math` (bits/mathinline.h): include the header, never write asm
  (the judge and the shared header refuse it). Only an instruction no header gives (`rdtsc`) is the
  program's own inline asm: set it aside.
- A file's static function or global is in the program's symbol table under its own name: use it.

Things to try when registers or order differ
- Reorder local declarations; introduce or drop a temporary; reuse a variable.
- `for` vs `while` vs `do { } while`; early `return` vs one return at the end; `if (a && b)` vs nested ifs.
- `int` vs `short`/`char` locals (extensions), signed vs unsigned (compares: `jl`/`jb`).
- Pointer walking (`*p++`) vs indexing (`p[i]`).

Machine drafts are Ghidra's (m2c reads no x86): `undefined4` is a 4-byte word, `param_1` the first argument,
`*(int *)(param_1 + 0x1c)` a field at +0x1c of the struct it points at. Replace them with the program's types from
the brief and get_context; autopilot already tried each draft as it is.
