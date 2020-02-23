asmdot.py
---------

Generate dot(1) graphs from x86 assembly source code. Each node is an
instruction; instructions from one block are grouped. A block is
everything between two consecutive labels.

This script can also detect x86-64 registers (in AT&T or Intel syntax)
and list all registers and instructions used in a block.
