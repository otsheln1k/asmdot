#!/usr/bin/env python3


# Utilities

# usage: (line_number, regs) list -> (reg: line_number list) dict
# [(key, [val])] -> {(val: [key])}
def dictzip(kvs):
    d = {}
    for k, vs in kvs:
        for v in vs:
            l = d.get(v)
            if l is None:
                d[v] = [k]
            else:
                l.append(k)
    return d

def append_dedup(it):
    l = []
    for x in it:
        l.extend(x)
    return list(set(l))



import re
import enum
import sys
from collections import namedtuple
import argparse


# Reading code

AssemblerSyntax = enum.Enum("AssemblerSyntax",
                            ["INTEL", "ATT"])

CharClass = enum.Enum('CharClass',
                      ['MISC', 'SEPARATOR', 'LINE_COMMENT'])

def char_class_att(c):
    return {'#': CharClass.LINE_COMMENT,
            ';': CharClass.SEPARATOR}.get(c, CharClass.MISC)

def char_class_intel(c):
    return {';': CharClass.LINE_COMMENT,
            '$': CharClass.SEPARATOR}.get(c, CharClass.MISC)

char_class_funcs = {
    AssemblerSyntax.INTEL: char_class_intel,
    AssemblerSyntax.ATT: char_class_att,
}

# file -> (line_number, text) get
def read_asm_lines(f, ch_class):
    for i, l in enumerate(f):
        escape = False
        quote = None
        acc = ""
        for c in l:
            if c == '\\':
                escape = True
            elif c in "\"'" \
                 and not escape \
                 and (quote is None or c == quote):
                quote = c if quote is None else None
            elif not quote:
                cls = ch_class(c)
                if cls == CharClass.LINE_COMMENT:
                    break
                elif cls == CharClass.SEPARATOR:
                    yield i, acc
                    acc = ""
                    continue

            acc += c
        if acc:
            yield i, acc

# str -> str gen
def get_args(rest):
    escape = False
    quote = None
    delims = []
    acc = ""
    for c in rest:
        if c == '\\':
            escape = True
        elif c in "\"'" \
             and not escape \
             and (quote is None or c == quote):
            quote = c if quote is None else None
        elif quote:
            pass
        elif c in "([":
            delims.append(c)
        elif c in ")]":
            pair = delims.pop() + c
            if pair not in ('()', '[]'):
                raise ValueError(f"Bad delimiters: {pair!r}")
        elif delims:
            pass
        elif c == ',':
            yield acc.strip()
            acc = ""
            continue
        acc += c
        if escape:
            escape = False
    if acc:
        yield acc.strip()

# str -> (label, instruction, args)
def split_line(line):
    sline = line.strip();
    ll = sline.split(':', 1)
    if len(ll) > 1:
        label, rest = ll
    else:
        label = None
        rest = ll[0]
    il = rest.strip().split(None, 1)
    return label, (il[0] if il else None), \
        list(get_args(il[1])) if len(il) > 1 else []


# Register searching

register_regexps = [
    # See info (as) i386-Regs
    r"[abcd][lhx]",
    r"[er][abcd]x",
    r"[er]?ip",
    r"r([89]|1[0-5])[dwb]?",
    r"[er]?[sb]p",
    r"[er]?[sd]i",
    r"[cdsefg]s",
    r"cr[0-48]",
    r"db[0-367]",
    r"tr[67]",
    r"st(\([0-7]\))?",
    r"[xyz]mm([0-9]|[12][0-5]|3[01])",
    r"[sd]il",
    r"[sb]pl",
    r"k[0-7]"
]

compile_regexps = lambda l: list(map(lambda s: re.compile(s, re.I), l))

register_common_regexp_att = re.compile(r"%\w+")
register_regexps_att = compile_regexps(
    map(lambda s: f'%{s}', register_regexps))

# str -> str gen
def extract_regs_att(s):
    for reg in register_common_regexp_att.findall(s):
        for regexp in register_regexps_att:
            if regexp.fullmatch(reg):
                break
        else:
            raise ValueError(f"Unknown register: {reg!r}")
        yield reg

register_regexps_intel = compile_regexps(
    map(lambda s: f"\\b{s}\\b", register_regexps))

def extract_regs_intel(s):
    for regexp in register_regexps_intel:
        for reg in regexp.findall(s):
            yield reg

extract_regs_funcs = {
    AssemblerSyntax.INTEL: extract_regs_intel,
    AssemblerSyntax.ATT: extract_regs_att,
}


# Instruction categories

InstructionCategory = enum.Enum("InstructionCategory",
                           ["PSEUDOOP", "JUMP", "JUMP_AWAY",
                            "RETURN", "MISC"])

def instruction_cat_is_jump(cat):
    return cat in (InstructionCategory.JUMP,
                   InstructionCategory.JUMP_AWAY)

def instruction_cat_is_nofallthrough(cat):
    return cat in (InstructionCategory.JUMP_AWAY,
                   InstructionCategory.RETURN)

# Note: order is significant
instruction_category_pred_table = [
    (InstructionCategory.PSEUDOOP, lambda s: s.startswith('.')),
    (InstructionCategory.JUMP_AWAY, lambda s: s == 'jmp'),
    (InstructionCategory.RETURN, lambda s: s in ('ret', 'retf')),
    (InstructionCategory.JUMP,
     lambda s: s in ('call', 'loop') or s.startswith('j')),
]

# str -> InstructionCategory
def instruction_category(instruction):
    lower = instruction.lower()
    for cat, pred in instruction_category_pred_table:
        if pred(lower):
            return cat
    return InstructionCategory.MISC


# Build the internal representation of the graph

class Block:
    def __init__(self, name, line):
        self._lines = []
        self._names = [name]
        self._regs = []
        self._ops = set()
        self._line = line

    def push(self, nl, line, regs=None, op=None):
        self._lines.append((nl, line))
        if regs is not None:
            self._regs.append((nl, map(str.lower, regs)))
        if op is not None:
            self._ops.add(op.lower())

    def add_name(self, name):
        self._names.append(name)

    def names(self):
        return self._names

    def ops(self):
        return self._ops

    def regs(self):
        return dictzip(self._regs)

    def lines(self):
        return self._lines

    def starting_line(self):
        return self._line

    def empty(self):
        return self._lines == []

JumpType = enum.Enum("JumpType",
                     ["NORMAL", "NEXT"])
JumpTableEntry = namedtuple("JumpTableEntry",
                            ["block", "index", "dest_block", "type"])

# (line_number, line) iter => (blocks, jtab)
def get_structure(line_iter, regs_function):
    blocks = []
    jtab = []
    B = lambda: blocks[-1]
    prev_seq = False
    for idx, line in line_iter:
        label, instr, rest = split_line(line)

        if label is not None:
            if blocks and B().empty():
                B().add_name(label)
            else:
                if prev_seq:
                    jtab.append(JumpTableEntry(
                        B(), None, label, JumpType.NEXT))
                blocks.append(Block(label, idx))

        if instr is None:
            continue

        cat = instruction_category(instr)

        if cat != InstructionCategory.PSEUDOOP:
            if not blocks:
                blocks.append(Block(None, 0))

            prev_seq = not instruction_cat_is_nofallthrough(cat)

            if instruction_cat_is_jump(cat):
                dest = rest[-1].rsplit(None, 1)[-1]
                jtab.append(JumpTableEntry(
                    B(), idx, dest, JumpType.NORMAL))

            regs = append_dedup(map(regs_function, rest))
            linstr = instr.lower()

            B().push(idx, (instr, rest), regs, linstr)

    return blocks, jtab


# Graph writing functions

GraphDisplayFlags = enum.IntFlag('GraphDisplayFlags',
                                 ['REGISTERS', 'INSTRUCTIONS'])

def block_name(b):
    return f"block_at_{b.starting_line()}"

def rebuild_line(instr, args):
    args_s = ' ' + ','.join(args) if args else ''
    return f"<FONT COLOR=\"blue4\">{instr}</FONT>{args_s}"

def write_line(f, nl, line_parts, alt=False):
    style = 'BGCOLOR="gray78"' if not alt else 'BGCOLOR="gray70"'
    print(
f"""<TR>
<TD {style}><FONT COLOR="gray30">{nl+1}</FONT></TD>
<TD {style} ALIGN="LEFT" PORT="l{nl}">{rebuild_line(*line_parts)}</TD>
</TR>""", file=f)

def block_title(name):
    return '(start)' if name is None else f"{name}:"

def write_block(f, b, flags):
    print(
f"""{block_name(b)} [label=<
<TABLE CELLSPACING="0" CELLPADDING="4" CELLBORDER="0">""")

    for n in b.names():
        print(f"""
<TR><TD COLSPAN="2" ALIGN="LEFT"><B>
{block_title(n)}
</B></TD></TR>""", file=f)

    if flags & GraphDisplayFlags.REGISTERS:
        for reg, lines in b.regs().items():
            print(
f"""<TR>
<TD ALIGN="CENTER" COLSPAN="2">
<FONT COLOR="red">
{reg}: {' '.join(map(lambda x: str(x+1), lines))}
</FONT></TD></TR>""", file=f)

    if flags & GraphDisplayFlags.INSTRUCTIONS:
        ops = b.ops()
        if ops:
            print(
f"""<TR>
<TD ALIGN="CENTER" COLSPAN="2">
<FONT COLOR="darkslateblue">
{', '.join(sorted(ops))}
</FONT></TD></TR>""", file=f)

    alt = False
    for i, l in b.lines():
        write_line(f, i, l, alt)
        alt = not alt

    print("</TABLE>>];", file=f)

def write_edge(f, src_b, src_nl, dst_b, jump_type):
    src_bn = block_name(src_b)
    dst_bn = block_name(dst_b)
    port = f':l{src_nl}' if jump_type == JumpType.NORMAL else ':s'
    print(f"{src_bn}{port} -> {dst_bn}:n;")

def write_graph(f, name, blocks, jtab, flags):
    print("digraph \"%s\" {" % name, file=f)
    print("node [shape=plaintext, style=filled, color=\"gray85\"];")

    for b in blocks:
        write_block(f, b, flags)

    block_dict = {n: b for b in blocks for n in b.names()}
    for e in jtab:
        src_b, src_nl, dst_bn, jump_type = e
        dst_b = block_dict[dst_bn]
        write_edge(f, src_b, src_nl, dst_b, jump_type)

    print("}")



def main():
    parser = argparse.ArgumentParser(
        description=
        "Generate a dot(1) control flow graph from x86 assembly source")

    syntax_tab = {"att": AssemblerSyntax.ATT,
                  "intel": AssemblerSyntax.INTEL}
    parser.add_argument("-s", "--syntax",
                        choices=list(syntax_tab.keys()),
                        default='att')
    parser.add_argument("-r", "--registers",
                        action='store_const',
                        const=GraphDisplayFlags.REGISTERS,
                        default=0)
    parser.add_argument("-i", "--instructions",
                        action='store_const',
                        const=GraphDisplayFlags.INSTRUCTIONS,
                        default=0)

    parser.add_argument("filename", nargs='?', default='-')

    ns = parser.parse_args()
    name = ns.filename
    syntax = syntax_tab[ns.syntax]
    flags = ns.registers | ns.instructions

    f = sys.stdin if name == '-' else open(name, 'r')

    char_class_func = char_class_funcs[syntax]
    regs_func = extract_regs_funcs[syntax]

    b, j = get_structure(
        read_asm_lines(f, char_class_func),
        regs_func)
    write_graph(sys.stdout, name, b, j, flags)
    return 0

if __name__ == "__main__":
    exit(main())
