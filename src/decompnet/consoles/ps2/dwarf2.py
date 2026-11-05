"""DWARF 2 and later: how GCC 3 and newer describe a program's types, functions and variables when it's built with
-g (.debug_info, with .debug_abbrev, .debug_str and .debug_loc). pyelftools parses the format; this turns its
entries into what stabs.py makes of STABS (and dwarf1.py of DWARF 1), so the shared header (cheader.py) and the
briefs work unchanged: per compile unit its named types, its functions with their parameters and locals, and its
global and static variables.

A Linux program of 2008 built by GCC 4.3 with -g has it (and no STABS): its import read only its symbol table, so
agents saw no types, prototypes or locals. Types refer to each other by the offset of their entry, across compile
units too (a header's struct is written once per unit that uses it; each unit's copy is read).

Where a parameter or local lives: a register (DW_OP_reg*), a static's address (DW_OP_addr), or an offset from the
function's frame base (DW_OP_fbreg). GCC 4 on i386 makes the frame base the call frame's address, which is ebp+8 in
the body of a function with a frame: an fbreg offset is said as ebp's (`frame offset +0x8` is the first argument),
as GCC 2.95's STABS say it. A location list (a variable that moves while the function runs) is said by its last
entry, where the function's body keeps it.
"""

from __future__ import annotations

from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.elf.elffile import ELFFile

from .stabs import BITS_PER_BYTE, POINTER_BYTES, Field, Function, SourceInfo, Type, Variable

TYPE_TAGS = ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type", "DW_TAG_enumeration_type",
             "DW_TAG_typedef", "DW_TAG_base_type")
FLOAT_ENCODINGS = (0x4,)  # DW_ATE_float
UNSIGNED_ENCODINGS = (0x1, 0x2, 0x7, 0x8)  # DW_ATE_address, boolean, unsigned, unsigned_char
I386_REGISTERS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")  # GCC's DWARF numbers on i386 ELF
I386_X87_FIRST = 11  # st(0)..st(7)
CPLUSPLUS_LANGUAGES = (0x4, 0x1A, 0x21, 0x2A)  # DW_LANG_C_plus_plus, _03, _11, _14
FRAME_POINTER = "ebp"
FRAME_BASE_EBP = 8  # GCC 4's frame base on i386 (the CFA) is ebp+8 in a function's body


def _same(a: list, b: list) -> bool:
    """Two parameter lists of the same types (the same entries)."""
    return len(a) == len(b) and all(x[1] is y[1] for x, y in zip(a, b))


def i386_register(number: int) -> str:
    if 0 <= number < len(I386_REGISTERS):
        return I386_REGISTERS[number]
    if I386_X87_FIRST <= number < I386_X87_FIRST + 8:
        return f"st({number - I386_X87_FIRST})"
    return f"register {number}"


def has_dwarf(elf: ELFFile) -> bool:
    return elf.get_section_by_name(".debug_info") is not None


class _Reader:
    def __init__(self, dwarf, registers, frame_base: int):
        self.dwarf, self.registers, self.frame_base = dwarf, registers, frame_base
        self.expr = DWARFExprParser(dwarf.structs)
        self.types: dict[int, Type] = {}
        self.void = Type(kind="void", name="void")
        self.locations = dwarf.location_lists() if dwarf.has_debug_info else None

    # ------------------------------------------------------------------ types

    @staticmethod
    def origin(die):
        """Where a DIE's name, type and the rest are: itself, or the entry it's a concrete copy of
        (DW_AT_abstract_origin: GCC 4's out-of-line copy of a function it also inlined, and that copy's parameters),
        or the declaration it defines (DW_AT_specification)."""
        for _ in range(4):
            name = next((a for a in ("DW_AT_abstract_origin", "DW_AT_specification") if a in die.attributes), None)
            if name is None or "DW_AT_name" in die.attributes:
                return die
            try:
                die = die.get_DIE_from_attribute(name)
            except Exception:  # noqa: BLE001
                return die
        return die

    def type_of(self, die) -> Type:
        """The type a DIE's DW_AT_type says; void when it has none (a function returning nothing, void *)."""
        die = die if "DW_AT_type" in die.attributes else self.origin(die)
        if "DW_AT_type" not in die.attributes:
            return self.void
        try:
            return self.defined(die.get_DIE_from_attribute("DW_AT_type"))
        except Exception:  # noqa: BLE001  a reference this reader can't follow: what it names stays unknown
            return Type()

    def defined(self, die) -> Type:
        """The type a DIE defines, made once (a struct with a pointer to itself finds itself being made)."""
        if die.offset in self.types:
            return self.types[die.offset]
        t = self.types[die.offset] = Type()
        try:
            self._define(die, t)
        except (KeyError, ValueError, RecursionError):
            pass
        return t

    @classmethod
    def _name(cls, die) -> str:
        a = die.attributes.get("DW_AT_name") or cls.origin(die).attributes.get("DW_AT_name")
        return a.value.decode("latin-1") if a is not None and isinstance(a.value, bytes) else ""

    @staticmethod
    def _int(die, name: str, default: int = 0) -> int:
        a = die.attributes.get(name)
        return a.value if a is not None and isinstance(a.value, int) else default

    def _define(self, die, t: Type) -> None:
        tag, name, size = die.tag, self._name(die), self._int(die, "DW_AT_byte_size")
        if tag == "DW_TAG_base_type":
            encoding = self._int(die, "DW_AT_encoding")
            t.kind = "float" if encoding in FLOAT_ENCODINGS else "base"
            t.name, t.size = name, size
            t.signed = encoding not in UNSIGNED_ENCODINGS
        elif tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type"):
            t.kind, t.target, t.size = "pointer", self.type_of(die), size or POINTER_BYTES
            t.reference = tag == "DW_TAG_reference_type"
        elif tag in ("DW_TAG_const_type", "DW_TAG_volatile_type"):
            t.kind, t.target = ("const" if tag == "DW_TAG_const_type" else "volatile"), self.type_of(die)
        elif tag == "DW_TAG_typedef":
            t.kind, t.typedef, t.target = "alias", name, self.type_of(die)
        elif tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type", "DW_TAG_enumeration_type"):
            kind = {"DW_TAG_union_type": "union", "DW_TAG_enumeration_type": "enum"}.get(tag, "struct")
            if "DW_AT_declaration" in die.attributes:  # known by name only here
                t.kind, t.xref, t.name = "xref", kind, name
                return
            t.kind, t.tag, t.size = kind, name, size or (4 if kind == "enum" else 0)
            own = self._own_class(die, name)
            for child in die.iter_children():
                if child.tag == "DW_TAG_member":
                    t.fields.append(self._member(child))
                elif child.tag == "DW_TAG_enumerator":
                    t.enumerators.append((self._name(child), self._int(child, "DW_AT_const_value")))
                elif child.tag == "DW_TAG_inheritance":
                    t.bases.append((self._offset(child) * BITS_PER_BYTE, self.type_of(child)))
                elif child.tag == "DW_TAG_subprogram" and self._name(child) and own and \
                        "DW_AT_artificial" not in child.attributes:  # (operator=, copy constructors C++ makes itself)
                    method = self._method(child)
                    if not any(m[0] == method[0] and _same(m[2], method[2]) and m[3] == method[3] for m in t.methods):
                        t.methods.append(method)  # (GCC 4.3 declares a constructor once per variant: C1, C2)
        elif tag == "DW_TAG_subroutine_type":
            t.kind, t.target = "function", self.type_of(die)
        elif tag == "DW_TAG_array_type":
            counts = []
            for child in die.iter_children():
                if child.tag == "DW_TAG_subrange_type":
                    if "DW_AT_count" in child.attributes:
                        counts.append(self._int(child, "DW_AT_count"))
                    elif "DW_AT_upper_bound" in child.attributes:
                        counts.append(self._int(child, "DW_AT_upper_bound") - self._int(child, "DW_AT_lower_bound") + 1)
                    else:
                        counts.append(0)  # (an array of no stated size: `extern int table[];`)
            element = self.type_of(die)
            for count in reversed(counts[1:]):
                element = Type(kind="array", count=count, target=element)
            t.kind, t.count, t.target = "array", counts[0] if counts else 0, element

    @staticmethod
    def _own_class(die, name: str) -> bool:
        """Whether a class's methods can be declared in the header, which is flat: not a template's instance
        (`allocator<char>` is written `allocator_char_`, which its constructor can't be) and not one in a namespace or
        another class (`Ogre::MaterialPtr`: its methods' symbols say the namespace, which a method defined from the
        header wouldn't). GCC 4.3 doesn't always write the namespace around a class; its methods' linkage names
        (`_ZN4Ogre11MaterialPtrC1Ev`) say it."""
        declared = die
        while "DW_AT_specification" in declared.attributes:  # (GCC writes a namespace's class's definition at the
            try:                                               # top of its unit, pointing to its declaration in it)
                declared = declared.get_DIE_from_attribute("DW_AT_specification")
            except Exception:  # noqa: BLE001
                break
        parent = declared.get_parent()
        if not name or "<" in name or parent is not None and parent.tag != "DW_TAG_compile_unit":
            return False
        own = (f"_ZN{len(name)}{name}", f"_ZNK{len(name)}{name}")
        for child in die.iter_children():
            linkage = child.attributes.get("DW_AT_MIPS_linkage_name") or child.attributes.get("DW_AT_linkage_name")
            if child.tag == "DW_TAG_subprogram" and linkage is not None and \
                    not linkage.value.decode("latin-1").startswith(own):
                return False
        return True

    def _method(self, die) -> tuple[str, Type, list[tuple[str, Type]], bool, bool]:
        """A method as its class declares it: a parameter GCC made (`this`, DW_AT_artificial) isn't written; a method
        without one is static, one whose `this` points to const is const."""
        params, this = [], None
        for child in die.iter_children():
            if child.tag != "DW_TAG_formal_parameter":
                continue
            if "DW_AT_artificial" in child.attributes:
                this = this or self.type_of(child)
            else:
                params.append((self._name(child), self.type_of(child)))
        const = this is not None and this.kind == "pointer" and this.target is not None and this.target.kind == "const"
        return self._name(die), self.type_of(die), params, const, this is None

    def qualified(self, die) -> str:
        """A function's name with its classes and namespaces (`CRandStoryData::CRandStoryData`): those its
        declaration is inside."""
        declared = die
        for _ in range(8):  # (a constructor's code -> its abstract entry -> its declaration in the class)
            link = next((a for a in ("DW_AT_specification", "DW_AT_abstract_origin") if a in declared.attributes), None)
            if link is None:
                break
            try:
                declared = declared.get_DIE_from_attribute(link)
            except Exception:  # noqa: BLE001
                break
        parts, parent = [self._name(die)], declared.get_parent()
        while parent is not None and parent.tag in ("DW_TAG_class_type", "DW_TAG_structure_type",
                                                    "DW_TAG_union_type", "DW_TAG_namespace"):
            parts.insert(0, self._name(parent) or "(anonymous)")
            while "DW_AT_specification" in parent.attributes:  # (a class defined outside its namespace: where it's
                try:                                             # declared says the namespace)
                    parent = parent.get_DIE_from_attribute("DW_AT_specification")
                except Exception:  # noqa: BLE001
                    break
            parent = parent.get_parent()
        return "::".join(parts)

    def _offset(self, die) -> int:
        """A member's offset: a constant, or (DWARF 2) a block `DW_OP_plus_uconst offset`."""
        a = die.attributes.get("DW_AT_data_member_location")
        if a is None:
            return 0
        if isinstance(a.value, int):
            return a.value
        ops = self._ops(a.value)
        return next((op.args[0] for op in ops if op.op_name == "DW_OP_plus_uconst"), 0)

    def _member(self, die) -> Field:
        """A member as stabs has it, offset and size in bits. DWARF 2 and 3 count a bitfield's DW_AT_bit_offset from
        the most significant bit of its storage unit (DW_AT_byte_size); on a little-endian processor the field's
        lowest bit is that many bits less from the top (DWARF 4's DW_AT_data_bit_offset counts from the low bit)."""
        bit_offset = self._offset(die) * BITS_PER_BYTE
        bit_size = self._int(die, "DW_AT_bit_size")
        if bit_size:
            if "DW_AT_data_bit_offset" in die.attributes:
                bit_offset = self._int(die, "DW_AT_data_bit_offset")
            else:
                unit = self._int(die, "DW_AT_byte_size") or self.type_of(die).size or 4
                bit_offset += unit * BITS_PER_BYTE - self._int(die, "DW_AT_bit_offset") - bit_size
        return Field(self._name(die), self.type_of(die), bit_offset, bit_size)

    # ------------------------------------------------------------------ where things live

    def _ops(self, block):
        try:
            return self.expr.parse_expr(block)
        except Exception:  # noqa: BLE001
            return []

    def where(self, die) -> tuple[str, int | None]:
        """Where a parameter or variable lives ("" when the debug information doesn't say), and a static's address."""
        a = die.attributes.get("DW_AT_location")
        if a is None:
            return "", None
        block = a.value
        if a.form in ("DW_FORM_data4", "DW_FORM_data8", "DW_FORM_sec_offset") and self.locations is not None:
            try:
                entries = self.locations.get_location_list_at_offset(a.value)
                block = entries[-1].loc_expr if entries else None
            except Exception:  # noqa: BLE001
                block = None
            if block is None:
                return "", None
        ops = self._ops(block)
        if not ops:
            return "", None
        op = ops[0]
        name = op.op_name
        if name.startswith("DW_OP_reg") and name != "DW_OP_regx":
            return self.registers(int(name[len("DW_OP_reg"):])), None
        if name == "DW_OP_regx":
            return self.registers(op.args[0]), None
        if name == "DW_OP_addr":
            return "static", op.args[0]
        if name == "DW_OP_fbreg":
            return f"the stack, frame offset {op.args[0] + self.frame_base:+#x}", None
        if name.startswith("DW_OP_breg"):
            number = op.args[0] if name == "DW_OP_bregx" else int(name[len("DW_OP_breg"):])
            offset = op.args[-1]
            if self.registers(number) == FRAME_POINTER:  # (as fbreg's, and STABS', are said)
                return f"the stack, frame offset {offset:+#x}", None
            return f"the stack at {self.registers(number)}{offset:+#x}", None
        return "", None

    def variable(self, die) -> Variable:
        where, address = self.where(die)
        return Variable(self._name(die), self.type_of(die), where, address)

    # ------------------------------------------------------------------ functions and units

    def function(self, die) -> Function | None:
        low = die.attributes.get("DW_AT_low_pc")
        if low is None:
            return None
        high = die.attributes.get("DW_AT_high_pc")
        size = 0
        if high is not None:  # an address (DWARF 2, 3), or from DWARF 4 a constant: the size
            size = high.value - low.value if high.form == "DW_FORM_addr" else high.value
        source = self.origin(die)  # (its name, type and line: the abstract entry of a function GCC also inlined)
        function = Function(self.qualified(die), low.value, self.type_of(die),
                            is_static="DW_AT_external" not in source.attributes,
                            size=max(0, size), line=self._int(source, "DW_AT_decl_line"))
        stack = list(reversed(list(die.iter_children())))
        while stack:  # the locals of its blocks too
            child = stack.pop()
            if child.tag == "DW_TAG_formal_parameter" and self._name(child):
                if "DW_AT_artificial" in self.origin(child).attributes:  # (C++'s `this`: the method's own)
                    continue
                function.params.append(self.variable(child))
            elif child.tag == "DW_TAG_variable" and self._name(child):
                function.locals.append(self.variable(child))
            elif child.tag == "DW_TAG_lexical_block":
                stack += reversed(list(child.iter_children()))
        return function

    def unit(self, cu) -> SourceInfo:
        top = cu.get_top_DIE()
        info = SourceInfo(self._name(top) or f"unit_{cu.cu_offset:X}",
                          cplusplus=self._int(top, "DW_AT_language") in CPLUSPLUS_LANGUAGES)
        # every type the unit names, wherever it's declared: in a namespace, a class, or (GCC 4.3) inside a method's
        # declaration in its class, where Ogre's typedefs of a parameter are; a field of one was left undefined
        for die in cu.iter_DIEs():
            if die.tag in TYPE_TAGS and die.tag != "DW_TAG_base_type" and self._name(die):
                info.types.append(self.defined(die))
        stack = [(child, False) for child in reversed(list(top.iter_children()))]
        while stack:
            die, in_function = stack.pop()
            try:
                if die.tag == "DW_TAG_subprogram":
                    if (function := self.function(die)) is not None:
                        info.functions.append(function)
                elif die.tag == "DW_TAG_variable" and self._name(die) and not in_function:
                    variable = self.variable(die)
                    if "DW_AT_external" in die.attributes:
                        if "DW_AT_declaration" not in die.attributes or variable.address is not None:
                            info.globals.append(variable)
                    elif variable.address is not None:
                        info.statics.append(variable)
            except (KeyError, ValueError, RecursionError):
                info.skipped += 1
            if die.tag == "DW_TAG_namespace":  # C++: the functions and variables a namespace declares
                stack += [(c, in_function) for c in reversed(list(die.iter_children()))]
        return info


def read(elf: ELFFile, registers=i386_register, frame_base: int = FRAME_BASE_EBP) -> list[SourceInfo]:
    """What a program's DWARF 2+ says, one SourceInfo per compile unit, named by its source path. `registers`: the
    processor's names for DWARF's register numbers; `frame_base`: what an fbreg offset adds to be said from the
    frame pointer."""
    if not has_dwarf(elf):
        return []
    dwarf = elf.get_dwarf_info(relocate_dwarf_sections=True)
    reader = _Reader(dwarf, registers, frame_base)
    return [reader.unit(cu) for cu in dwarf.iter_CUs()]
