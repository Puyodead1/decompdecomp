# Matching GCC on Linux (32-bit x86 programs)

The project's settings name the program's own compiler, read from its `.comment`: Slackware 8.0's GCC 2.95.3
(programs of 2000-2002) or Debian 5.0's GCC 4.3.2 (2008-2009), usually `-O2` (search_flags tries `-O1`, `-O3` and
others on a function). C, cdecl. Most of this guide is GCC 2.95's habits; GCC 4.3's differ where its section says.

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
- A jump the game encodes long (`e9`, 5 bytes) where 2 reach: gas made it so assembling the whole file. When your C
  is that close, the judge also tries it where the earlier code of its file put it, and it matches if the rest is
  right. If every instruction matches and only an encoding still differs, say so in a note and release it.

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

GCC 4.3 (a program whose `.comment` says 4.3.2)
- Arguments are stored, not pushed: the frame reserves the outgoing space once (`sub esp, N` after the saved
  registers) and each call is `mov [esp+8], ..; mov [esp+4], ..; mov [esp], ..; call f`, with no `add esp` after it.
  The order of those stores is the compiler's: get the arguments right, not their order.
- The frame saves registers before it reserves space: `push ebp; mov ebp, esp; push edi; push esi; push ebx;
  sub esp, N`, and ends `add esp, N; pop ebx; pop esi; pop edi; pop ebp; ret`.
- At -O2 it inlines a `static` function called from one place, and small ones from several: a function the
  assembly doesn't call but whose code appears inside another was a static helper of its file. Write it as one, in
  the same source, and the judge's compile inlines it the same way.
- Loops are padded with the long nops (`lea esi, [esi+eiz*1+0]`, `nop word [eax+eax]`), as 2.95's are: never
  write them. Counting loops often count up with `add reg, 1` (not `inc`): that's -mtune=generic, not the C.
- glibc 2.7's headers come with it: include them as the game's files did (`<sys/io.h>`, `<math.h>`, ...).

C++ (a program built by Fedora's GCC 4.3.2, with classes)
- A function's name is its symbol (`_ZN14CRandStoryDataC1Ev`); the brief says it as written
  (`CRandStoryData::CRandStoryData()`). Write it so, `Class::method`, and the judge compiles your C as C++. C1 and C2
  (D1 and D2) are the same constructor (destructor) GCC writes twice: one definition makes both.
- The shared header declares the methods of the classes the debug information describes, for C++ only. A class it
  doesn't (no debug information, or one in a namespace) needs its methods declared: add them to the class in the
  header with edit_context, inside `#ifdef __cplusplus`, never as `virtual` (its vtable pointer is a member already).

Libraries the program has built in (Lua, boost...)
- When the project folder's libs/ has a library's own source, its functions that source makes are set aside as
  library code already, and its headers are in every compile: `#include <boost/shared_ptr.hpp>` works. The shared
  header has the program's types too, so in C a library header that defines the same ones (`typedef ... Byte`)
  clashes with it: include one only for what the shared header lacks, or in C++.
- A program's files weren't all built alike. A debug build's files (often those with debug information) are -O0:
  every use of a parameter reloads it from its stack slot (`mov eax, [ebp+8]` again and again) and nothing stays in
  esi or edi. Code like that won't match at -O2: call search_flags, which tries -O0 and the build machine's processor
  (-march=amdfam10, k8, core2), and suggest the file's range with the flags that match.
