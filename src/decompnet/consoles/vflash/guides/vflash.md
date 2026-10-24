# Matching V.Flash code (GCC 3.2.3 for ARM)

CPU: an ARM9 (ARM9TDMI-class, ARMv4T), ARM code only (no Thumb), little-endian; no FPU and no divide instruction:
`float`/`double` maths, `/` and `%` are calls to the runtime's helpers (`__divsi3`-style calls, soft-float `_dadd`,
`dmul`...): write the plain operator. Doubles are stored high word first (the old FPA order). The guide `arm` has
the instruction set: read it too.

The game: its firmware, FA (kernel, drivers, C and C++ runtime, zlib, Tremor, the maths library, the 3D engine and a
thin game layer), and its game modules, loaded one at a time into the same addresses, which call FA by address.
Each is a program of the project: `src/FA/text_<address>.cpp` for FA's functions, `src/<module>/text_<address>.cpp`
for a module's. Names say which: FA's `func_10A715C4` and `D_10B3B8FC`, a module's `func_GZ1A_1047B800` and
`D_GZ1A_10614000`. A module's code calling FA calls FA's names.

The compiler: GCC 3.2.3 (arm-elf) with binutils 2.14, always with `-fomit-frame-pointer -mno-apcs-frame
-msoft-float`. The project builds C++ (`.cpp`) with `-O3 -mcpu=arm9tdmi -fno-rtti`, what FA's engine and the game
modules' C++ were built with. Other parts of FA were built otherwise, and a file holding them needs its own flags
(search_flags tries them, and a file's flags are kept in config/<version>/flags.json):
- the maths library (newlib and fdlibm: `sin`, `__kernel_rem_pio2`, `tanh`...): C at `-O1 -mcpu=arm9tdmi`;
- zlib 1.2.3 and Tremor (the Ogg Vorbis decoder): C at `-O3 -mcpu=arm9tdmi`;
- C++ that doesn't match at `-O3`: try `-O2 -frename-registers` (the two are often the same code).
A C file is a `.c` source file: C++ (`.cpp`) mangles names and adds `-fno-rtti`, and the library code was C.

What GCC 3.2.3's code looks like:
- Returns: `mov pc, lr` in a leaf function, `ldmfd sp!, {r4-r6, pc}` after a `stmfd sp!, {r4-r6, lr}` prologue; no
  frame pointer, no `bx lr` from C.
- Tail calls at -O2 and up: `ldmfd sp!, {r4, lr}` then `b func` (a deleting destructor ends in `b operator delete`).
- Constructors and destructors are emitted twice (the complete-object and base-object copies, C1/C2 and D1/D2,
  with D0 the deleting destructor): two functions with the same code, one after the other.
- Switches: `cmp r0, #N; ldrls pc, [pc, r0, lsl #2]; b default` then a table of the cases' addresses, part of the
  function.
- Literal pools after each function hold its constants and addresses, in first-use order; a double constant is two
  words, loaded with `add rN, pc, #off; ldmia rN, {r2, r3}`.
- `-mcpu=arm9tdmi` schedules loads away from their use; without it the order differs.

Hand-written assembly: FA's soft-float and division runtime (fast, not IEEE-exact: `_dadd`, `dmul`, `__rt_udiv`...)
and the start-up code are the vendor's assembly, not compiler output: mark them asm rather than writing C.

Library code matches as it is: zlib 1.2.3, Tremor (the lowmem branch, 2005-2007) and newlib 1.12's libm are the
upstream sources, built with the flags above. The import found them already: `src/<program>/lib/<library>/` holds
each library source file the game has, its functions named by their library names, and most match from the start.
The ones that don't are what the game's makers changed (VTech gave a few zlib functions static buffers): edit the
library's function in place to what the game has, keeping its name.
