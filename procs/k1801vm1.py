# K1801BM1 - soviet clone of DEC LSI-11 CPU
# (c) 2019 by Yuriy Shestakov
# The code is based on implementation of DEC PDP-11 by Hex-Rays
# ---------------------------------------------------------------------
# import sys
import idaapi
from idaapi import *
# import idc

UAS_SECT = 0x0001  # Segments are named .SECTION
n_asect = -1
n_ovrbeg = -2
n_ovrend = -3
n_asciiX = -4
n_ovrbas = -5
o_fpreg = o_idpspec0
o_number = o_idpspec1

# values of CPU
CPU_PDP11 = 0
CPU_1801BM1 = 1
CPU_1801BM2 = 2

# values for insn_t.auxpref
AUX_SIZEMASK = 0x0F
AUX_NOSUF = 0x00  # no suffix (e.g. SWPB)
AUX_WORD = 0x01  # word transfer, .W suffix
AUX_BYTE = 0x02  # byte transfer, .B suffix


def is_bytecmd(insn):
    return (insn.auxpref & AUX_SIZEMASK) == AUX_BYTE


def set_bytecmd(insn):
    insn.auxpref &= (0xffff ^ AUX_SIZEMASK)
    insn.auxpref |= AUX_BYTE  # .bytecmd


def set_wordcmd(insn):
    insn.auxpref &= (0xffff ^ AUX_SIZEMASK)
    insn.auxpref |= AUX_WORD


def ill_imm(op):
    return op.specflag1


def addr16(op):
    return op.addr & 0xffff


def BITS(val, high, low):
    """
    extract bitfield occupying bits high..low from val
    (inclusive, start from 0)
    """
    return (val >> low) & ((1 << (high - low + 1)) - 1)


def BIT(val, bit):
    "extract one bit"
    return (val >> bit) & 1


class InvalidInsnError(Exception):
    pass


class PdpMl(object):
    """
    struct pdp_ml_t
    {
        uint32 ovrtbl_base;
        uint16 ovrcallbeg, ovrcallend, asect_top;
    };
    """
    def __init__(self, ovrtbl_base, ovrcallbeg, ovrcallend,
                 asect_top):
        self.ovrtbl_base = ovrtbl_base
        self.ovrcallbeg = ovrcallbeg
        self.ovrcallend = ovrcallend
        self.asect_top = asect_top


# ----------------------------------------------------------------------
class k1801bm1_processor_t(idaapi.processor_t):
    """
    Processor module classes must derive from idaapi.processor_t

    The required and optional attributes/callbacks are illustrated in
    this template
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 1

    # Processor features
    flag = PR_WORD_INS | PRN_OCT | PR_SEGTRANS

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['pdp11', 'k1801bm1', 'k1801bm2']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['DEC PDP-11', 'DEC 1801BM1', 'DEC 1801BM2']

    # register names
    reg_names = [
        # General purpose registers
        "R0", "R1", "R2", "R3",
        "R4", "R5", "SP", "PC",
        # FP registers
        "AC0", "AC1", "AC2", "AC3",
        "AC4", "AC5", "AC6", "AC7",
        # Fake segment registers
        "CS",
        "DS"
    ]

    # number of registers (optional: deduced from the len(reg_names))
    regs_num = len(reg_names)

    # Segment register information (use virtual CS and DS registers if your
    # processor doesn't have segment registers):
    reg_first_sreg = 16  # index of CS
    reg_last_sreg = 17   # index of DS

    # size of a segment register in bytes
    segreg_size = 0

    # You should define 2 virtual segment registers for CS and DS.

    # number of CS/DS registers
    reg_code_sreg = 16
    reg_data_sreg = 17

    # Array of typical code start sequences (optional)
    # codestart = [ ... ]

    # Array of 'return' instruction opcodes (optional)
    retcodes = [
        '\200\0',  # rts r0
        '\201\0',  # rts r1
        '\202\0',  # rts r2
        '\203\0',  # rts r3
        '\204\0',  # rts r4
        '\205\0',  # rts r5
        '\206\0',  # rts sp
        '\207\0',  # rts pc
        '\2\0',    # rti
        '\6\0',    # rtt
        '\12\0',   # start (BM1 spec, return to USER mode)
    ]

    # Array of instructions
    instruc = [
        {'name': '',  'feature': 0},  # placeholder for "not an instruction"

        {'name': 'halt',  'feature': CF_STOP, 'cmt': 'Stop CPU'},
        {'name': 'start', 'feature': CF_STOP, 'cmt': 'Start from HALT to USR'},
        {'name': 'step',  'feature': CF_STOP, 'cmt': 'Step from HALT to USR'},
        {'name': 'wait',  'feature': 0,       'cmt': 'Wait Interrupt'},
        {'name': 'rti',   'feature': CF_STOP, 'cmt': 'Interrupt return'},
        {'name': 'bpt',   'feature': CF_CALL, 'cmt': 'Trap to Debugger'},
        {'name': 'iot',   'feature': CF_CALL, 'cmt': 'Trap to 20'},
        {'name': 'reset', 'feature': 0,       'cmt': 'Reset CPU and device'},
        {'name': 'rtt',   'feature': CF_STOP,
                          'cmt': 'Interrupt return and ignore Dbf flag'},
        {'name': 'mfpt',  'feature': 0,       'cmt': 'Load processor type'},
        {'name': 'jmp',   'feature': CF_USE1 | CF_STOP,
                          'cmt': 'Jmp'},
        {'name': 'rts',   'feature': CF_USE1 | CF_STOP,
                          'cmt': 'Return into Subroutine'},
        {'name': 'spl',   'feature': CF_USE1,
                          'cmt': 'Set CPU Prioritet (>11-70)'},
        {'name': 'nop',   'feature': 0,        'cmt': 'Not operation'},
        {'name': 'clc',   'feature': 0,        'cmt': 'C=0'},
        {'name': 'clv',   'feature': 0,        'cmt': 'V=0'},
        {'name': 'clz',   'feature': 0,        'cmt': 'Z=0'},
        {'name': 'cln',   'feature': 0,        'cmt': 'N=0'},
        {'name': 'ccc',   'feature': 0,        'cmt': 'C=V=Z=N=0'},
        {'name': 'sec',   'feature': 0,        'cmt': 'C=1'},
        {'name': 'sev',   'feature': 0,        'cmt': 'V=1'},
        {'name': 'sez',   'feature': 0,        'cmt': 'Z=1'},
        {'name': 'sen',   'feature': 0,        'cmt': 'N=1'},
        {'name': 'scc',   'feature': 0,        'cmt': 'C=V=Z=N=1'},
        {'name': 'swab',  'feature': CF_USE1 | CF_CHG1,
                          'cmt': 'Exchange byte'},
        {'name': 'br',    'feature': CF_USE1 | CF_STOP,
                          'cmt': 'Relative Jmp'},
        {'name': 'bne',   'feature': CF_USE1,  'cmt': 'Jmp if Z=1'},
        {'name': 'beq',   'feature': CF_USE1,  'cmt': 'Jmp if Z=0'},
        {'name': 'bge',   'feature': CF_USE1,  'cmt': 'Jmp if N^V=0'},
        {'name': 'blt',   'feature': CF_USE1,  'cmt': 'Jmp if N^V=1'},
        {'name': 'bgt',   'feature': CF_USE1,  'cmt': 'Jmp if Z|(N^V)=0'},
        {'name': 'ble',   'feature': CF_USE1,  'cmt': 'Jmp if Z|(N^V)=1'},
        {'name': 'jsr',   'feature': CF_USE2 | CF_CALL | CF_CHG1,
                          'cmt': 'Call'},
        {'name': 'clr',   'feature': CF_CHG1,  'cmt': 'Clear'},
        {'name': 'com',   'feature': CF_USE1 | CF_CHG1, 'cmt': 'Reverse'},
        {'name': 'inc',   'feature': CF_USE1 | CF_CHG1, 'cmt': 'Increment'},
        {'name': 'dec',   'feature': CF_USE1 | CF_CHG1, 'cmt': 'Decrement'},
        {'name': 'neg',   'feature': CF_USE1 | CF_CHG1, 'cmt': 'op = -op'},
        {'name': 'adc',   'feature': CF_USE1 | CF_CHG1,
                          'cmt': 'Add with Carry'},
        {'name': 'sbc',   'feature': CF_USE1 | CF_CHG1,
                          'cmt': 'Substract with Carry'},
        {'name': 'tst',   'feature': CF_USE1,  'cmt': 'Test'},
        {'name': 'ror',   'feature': CF_USE1 | CF_CHG1,
                          'cmt': 'Cyclic shift right'},
        {'name': 'rol',   'feature': CF_USE1 | CF_CHG1,
                          'cmt': 'Cyclic shift left'},
        {'name': 'asr',   'feature': CF_USE1 | CF_CHG1,
                          'cmt': 'Arifmetic shift right'},
        {'name': 'asl',   'feature': CF_USE1 | CF_CHG1,
                          'cmt': 'Arifmetic shift left'},
        {'name': 'mark',  'feature': CF_USE1,
                          'cmt': 'Return and empty stack'},
        {'name': 'mfpi',  'feature': CF_USE1,
                          'cmt': 'Load from previous instr. space'},
        {'name': 'mtpi',  'feature': CF_USE1,
                          'cmt': 'Store to previous instr. space'},
        {'name': 'sxt',   'feature': CF_CHG1,  'cmt': 'N=>op'},
        {'name': 'mov',   'feature': CF_USE1 | CF_CHG2, 'cmt': 'Move'},
        {'name': 'cmp',   'feature': CF_USE1 | CF_USE2, 'cmt': 'Compare'},
        {'name': 'bit',   'feature': CF_USE1 | CF_USE2, 'cmt': "Test bit's"},
        {'name': 'bic',   'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': "Clear bit's"},
        {'name': 'bis',   'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': "Set bit's"},
        {'name': 'add',   'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Add'},
        {'name': 'sub',   'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Substract'},
        {'name': 'mul',   'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Multiple'},
        {'name': 'div',   'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Divide'},
        {'name': 'ash',   'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Multistep shift'},
        {'name': 'ashc',  'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Multistep shift 2 reg'},
        {'name': 'xor',   'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Exclusive or'},
        {'name': 'fadd',  'feature': CF_USE1 | CF_CHG1,
                          'cmt': 'Floating Add'},
        {'name': 'fsub',  'feature': CF_USE1 | CF_CHG1,
                          'cmt': 'Floating Substract'},
        {'name': 'fmul',  'feature': CF_USE1 | CF_CHG1,
                          'cmt': 'Floating Multiple'},
        {'name': 'fdiv',  'feature': CF_USE1 | CF_CHG1,
                          'cmt': 'Floating Divide'},
        {'name': 'sob',   'feature': CF_USE2 | CF_CHG1, 'cmt': 'Loop'},
        {'name': 'bpl',   'feature': CF_USE1, 'cmt': 'Jmp if N=0'},
        {'name': 'bmi',   'feature': CF_USE1, 'cmt': 'Jmp if N=1'},
        {'name': 'bhi',   'feature': CF_USE1, 'cmt': 'Jmp if ( !C)&(!Z )=0'},
        {'name': 'blos',  'feature': CF_USE1, 'cmt': 'Jmp if C|Z=1'},
        {'name': 'bvc',   'feature': CF_USE1, 'cmt': 'Jmp if V=0'},
        {'name': 'bvs',   'feature': CF_USE1, 'cmt': 'Jmp if V=1'},
        {'name': 'bcc',   'feature': CF_USE1, 'cmt': 'Jmp if C=0'},
        {'name': 'bcs',   'feature': CF_USE1, 'cmt': 'Jmp if C=1'},
        {'name': 'emt',   'feature': CF_USE1 | CF_CALL,
                          'cmt': 'Trap to system'},
        {'name': 'trap',  'feature': CF_USE1 | CF_CALL,
                          'cmt': 'Trap to user/compiler'},
        {'name': 'mtps',  'feature': CF_USE1,  'cmt': 'Store PSW'},
        {'name': 'mfpd',  'feature': CF_USE1,
                          'cmt': 'Load from previous data space'},
        {'name': 'mtpd',  'feature': CF_USE1,
                          'cmt': 'Store to previous data space'},
        {'name': 'mfps',  'feature': CF_USE1,  'cmt': 'Load PSW'},
        {'name': 'cfcc',  'feature': 0,
                          'cmt': 'Copy Cond.Codes into FPS to PSW'},
        {'name': 'setf',  'feature': 0, 'cmt': 'Set Float'},
        {'name': 'seti',  'feature': 0, 'cmt': 'Set Integer'},
        {'name': 'setd',  'feature': 0, 'cmt': 'Set Double'},
        {'name': 'setl',  'feature': 0, 'cmt': 'Set Long Integer'},
        {'name': 'ldfps', 'feature': CF_CHG1, 'cmt': 'Load FPS'},
        {'name': 'stfps', 'feature': CF_USE1, 'cmt': 'Store FPS'},
        {'name': 'stst',  'feature': 0, 'cmt': 'Load interrupt status'},
        {'name': 'clrd',  'feature': CF_CHG1, 'cmt': 'Clear'},
        {'name': 'tstd',  'feature': CF_USE1, 'cmt': 'Test'},
        {'name': 'absd',  'feature': CF_USE1 | CF_CHG1, 'cmt': 'op = mod(op)'},
        {'name': 'negd',  'feature': CF_USE1 | CF_CHG1, 'cmt': 'op = -op'},
        {'name': 'muld',  'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Multiple'},
        {'name': 'modd',  'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Load Int. part'},
        {'name': 'addd',  'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Add'},
        {'name': 'ldd',   'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Load Acc'},
        {'name': 'subd',  'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Substract'},
        {'name': 'cmpd',  'feature': CF_USE1 | CF_USE2, 'cmt': 'Compare'},
        {'name': 'std',   'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Store Acc'},
        {'name': 'divd',  'feature': CF_USE1 | CF_USE2 | CF_CHG2,
                          'cmt': 'Divide'},
        {'name': 'stexp', 'feature': CF_USE1, 'cmt': 'Store exponent'},
        {'name': 'stcdi', 'feature': CF_USE1 | CF_CHG2,
                          'cmt': 'Store and convert'},
        {'name': 'stcdf', 'feature': CF_USE1 | CF_CHG2,
                          'cmt': 'Store and convert'},
        {'name': 'ldexp', 'feature': CF_CHG1, 'cmt': 'Load exponent'},
        {'name': 'ldcif', 'feature': CF_USE2 | CF_CHG1,
                          'cmt': 'Load and convert int to float'},
        {'name': 'ldcid', 'feature': CF_USE2 | CF_CHG1,
                          'cmt': 'Load and convert int to double'},
        {'name': 'ldcfd', 'feature': CF_USE2 | CF_CHG1,
                          'cmt': 'Load and convert'},
        {'name': 'call',  'feature': CF_USE1 | CF_CALL, 'cmt': 'Jsr PC,'},
        {'name': 'return', 'feature': CF_STOP, 'cmt': 'Rts PC'},
        # 1801BM2 specific
        {'name': 'rsel', 'feature': 0,
                         'cmt': 'address-less read R0<-(SEL), HALT mode only'},
        {'name': 'mfus', 'feature': 0,
                         'cmt': 'fetch USER mem R0<-(R5)+, HALT mode only'},
        {'name': 'mtus', 'feature': 0,
                         'cmt': 'write USER mem R0->-(R5), HALT mode only'},
        {'name': 'rcpc', 'feature': 0,
                         'cmt': 'read PC copy: R0<-PC, HALT mode only'},
        {'name': 'rcps', 'feature': 0,
                         'cmt': 'read PSW copy: R0<-PSW, HALT mode only'},
        {'name': 'wcpc', 'feature': 0,
                         'cmt': 'write PC copy: R0->PC, HALT mode only'},
        {'name': 'wcps', 'feature': 0,
                         'cmt': 'write PSW copy: R0->PSW, HALT mode only'},
        # ...
        {'name': '.word', 'feature': 0, 'cmt': 'Complex Condition Codes'}
    ]

    # icode of the first instruction
    instruc_start = 0

    # icode of the last instruction + 1
    instruc_end = len(instruc) + 1

    # Size of long double (tbyte) for this processor
    # (meaningful only if ash.a_tbyte != NULL) (optional)
    tbyte_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats
    #                      (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    # real_width = (7, 7, 15, 0)

    # icode (or instruction number) of return instruction.
    # It is ok to give any of possible return instructions
    # icode_return = 5

    # 1801BM1 CPU specific commands
    bm1_cmd = dict()
    # 1801BM2 CPU specific commands
    bm2_cmd = dict()

    # only one assembler is supported
    macro11_assembler = {
        # flag
        'flag': (AS_COLON | AS_2CHRE | AS_NCHRE | ASH_HEXF5 | ASO_OCTF2 |
                 ASD_DECF2 | AS_NCMAS | AS_ONEDUP | ASB_BINF1 | AS_RELSUP),

        # user defined flags (local only for IDP) (optional)
        'uflag': UAS_SECT,

        # Assembler name (displayed in menus)
        'name': "MACRO-11 assembler",

        # array of automatically generated header lines they appear at
        # the start of disassembled text (optional)
        'header': [
            "",
            ".macro .array of,type,cnt,val",
            ".rept  cnt",
            " type  val",
            ".endr",
            ".endm .array",
        ],

        # org directive
        'origin': ".",

        # end directive
        'end': ".END",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\\",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character
        # and ascii constants)
        'esccodes': "\\\200",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': ".ascii",

        # byte directive
        'a_byte': ".byte",

        # word directive
        'a_word': ".word",

        # remove if not allowed
        'a_dword': ".long",

        # remove if not allowed
        # 'a_qword': "dq",

        # float;  4bytes; remove if not allowed
        'a_float': ".flt2",

        # double; 8bytes; NULL if not allowed
        'a_double': ".flt4",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': ".array of #hs cnt=#d val=#v",

        # uninitialized data directive
        # (should include '%s' for the size of data)
        'a_bss': ".blkb %s",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': "=",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': ".",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': ".globl",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': ".weak",

        # "extrn"  name keyword
        'a_extrn': ".globl",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': ".align",

        # Left and right braces used in complex expressions
        'lbrace': "<",
        'rbrace': ">",

        # %  mod     assembler time operation
        # 'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # !  bit not assembler time operation
        'a_bnot': "!",

        # << shift left assembler time operation
        # 'a_shl': "<<",

        # >> shift right assembler time operation
        # 'a_shr': ">>",

        # size of type (format string) (optional)
        # 'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments,
        # for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",

        # the include directive (format string) (optional)
        # 'a_include_fmt': ".incl %s",

        # if a named item is a structure and displayed
        # in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        # 'a_vstruc_fmt': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        # 'a_rva': "rva"

        # immediate op
        'imm': '#',
        'ph1_fmt': '@%s',
        'ph3_fmt': '@(%s)+',
        'ph5_fmt': '@-(%s)'
    }  # Assembler
    # GNU AS assember supports BSD syntax
    bsd_assembler = {
        # flag -
        # https://www.hex-rays.com/products/ida/support/sdkdoc/group___a_s__.html
        'flag': (AS_COLON | AS_2CHRE | AS_NCHRE | ASH_HEXF3 | ASO_OCTF1 |
                 ASD_DECF0 | AS_NCMAS | AS_ONEDUP | ASB_BINF3 | AS_RELSUP
                 # | AS_ASCIIC | AS_ASCIIZ
                 ),

        # user defined flags (local only for IDP) (optional)
        'uflag': UAS_SECT,

        # Assembler name (displayed in menus)
        'name': "BSD assembler",

        # array of automatically generated header lines they appear at
        # the start of disassembled text (optional)
        'header': [
            ".title generated_by_ida",
            '.ident "V00.00"',
            '.macro call    lbl',
            '   jsr     pc,\lbl',
            '.endm',
            '.macro return',
            '   rts     pc',
            '.endm',
            '.macro marray cmd,count,val',
            '  .rept \count',
            '  \cmd \\val',
            '  .endr',
            '.endm',
            '',
            '.text',
        ],

        # org directive
        'origin': ".",

        # end directive
        'end': ".end",

        # comment string (see also cmnt2)
        'cmnt': "//",

        # ASCII string delimiter
        'ascsep': '"',

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character
        # and ascii constants)
        'esccodes': "\\\"",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': ".ascii",

        # byte directive
        'a_byte': ".byte",

        # word directive
        # always 16bit: ".hword",
        # depending on target asm: ".int"
        'a_word': ".word",

        # remove if not allowed
        'a_dword': ".long",

        # remove if not allowed
        # 'a_qword': "dq",

        # float;  4bytes; remove if not allowed
        'a_float': ".flt2",

        # double; 8bytes; NULL if not allowed
        'a_double': ".flt4",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "marray #h,#d,#v",

        # uninitialized data directive
        # (should include '%s' for the size of data)
        'a_bss': ".skip %s",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': "=",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': ".",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': ".globl",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': ".weak",

        # "extrn"  name keyword
        'a_extrn': ".globl",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': ".align",

        # Left and right braces used in complex expressions
        'lbrace': "<",
        'rbrace': ">",

        # %  mod     assembler time operation
        # 'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # !  bit not assembler time operation
        'a_bnot': "!",

        # << shift left assembler time operation
        # 'a_shl': "<<",

        # >> shift right assembler time operation
        # 'a_shr': ">>",

        # size of type (format string) (optional)
        # 'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments,
        # for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",

        # the include directive (format string) (optional)
        # 'a_include_fmt': ".incl %s",

        # if a named item is a structure and displayed
        # in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        # 'a_vstruc_fmt': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        # 'a_rva': "rva"

        # immediate op
        'imm': '$',
        'ph1_fmt': '(%s)',
        'ph3_fmt': '*(%s)+',
        'ph5_fmt': '*-(%s)'
    }  # Assembler
    # assembler = macro11_assembler
    assembler = bsd_assembler

    ml = PdpMl(BADADDR, 0, 0, 0)
    ovrtrans = netnode('$ pdp-11 overlay translations')
    # ----------------------------------------------------------------------
    # The following callbacks are optional.
    # *** Please remove the callbacks that you don't plan to implement ***

    def notify_out_header(self, ctx):
        """function to produce start of disassembled text"""
        for m in self.assembler['header']:
            ctx.out_line(m)
            ctx.flush_outbuf(0)

        if (self.cpu_1801bm1 or self.cpu_1801bm2):
            for opcode, itype in self.bm1_cmd.items():
                self._out_1801_macro(ctx, opcode, self.instruc[itype]['name'])
        if self.cpu_1801bm2:
            for opcode, itype in self.bm2_cmd.items():
                self._out_1801_macro(ctx, opcode, self.instruc[itype]['name'])

    def _out_1801_macro(self, ctx, opcode, name):
        ctx.out_line(".macro %s" % name)
        ctx.flush_outbuf(0)
        ctx.out_line("\t.word %06o" % opcode)
        ctx.flush_outbuf(0)
        ctx.out_line(".endm")
        ctx.flush_outbuf(0)

    def notify_out_footer(self, ctx):
        """function to produce end of disassembled text"""
        ctx.out_line(self.assembler['end'])
        ctx.flush_outbuf(0)

    def notify_out_segstart(self, ctx, ea):
        """function to produce start of segment"""
        seg = getseg(ea)
        # kls = get_segm_class(seg)
        # st_a = idc.SegStart(ea)
        # end_a = idc.SegEnd(ea)
        # print "seg.ea: %005o kls: %s: st: %06o end: %06o" % \
        #        (ea, kls, st_a, end_a)
        if is_spec_segm(seg.type):
            return

    def notify_out_segend(self, ctx, ea):
        """function to produce end of segment"""
        pass

    def notify_out_assumes(self, ctx):
        """function to produce assume directives"""
        pass

    def notify_term(self):
        """called when the processor module is unloading"""
        pass

    def notify_setup_til(self):
        """Setup default type libraries
        (called after loading a new file into the database)
        The processor module may load tils, setup memory model and
        perform other actions required to set up the type system
        @return: None
        """
        pass

    def notify_newprc(self, nproc, keep_cfg):
        """
        Before changing proccesor type
        nproc - processor number in the array of processor names
        return >=0-ok,<0-prohibit
        """
        self._cpu = nproc
        return 0

    def notify_newfile(self, filename):
        """A new file is loaded (already)"""
        pass

    def notify_oldfile(self, filename):
        """An old file is loaded (already)"""
        self.ml.asect_top = self.ovrtrans.altval(n_asect & 0xffff)
        self.ml.ovrcallbeg = self.ovrtrans.altval(n_ovrbeg & 0xffff)
        self.ml.ovrcallend = self.ovrtrans.altval(n_ovrend & 0xffff)
        self.ml.ovrtbl_base = self.ovrtrans.altval(n_ovrbas & 0xffff)

    def notify_newbinary(self, filename, fileoff, basepara, binoff, nbytes):
        """
        Before loading a binary file
         args:
          filename  - binary file name
          fileoff   - offset in the file
          basepara  - base loading paragraph
          binoff    - loader offset
          nbytes    - number of bytes to load
        Returns nothing
        """
        pass

    def notify_undefine(self, ea):
        """
        An item in the database (insn or data) is being deleted
        @param args: ea
        @return: >=0-ok, <0 - the kernel should stop
                 if the return value is not negative:
                     bit0 - ignored
                     bit1 - do not delete srareas at the item end
        """
        return 1

    def notify_endbinary(self, ok):
        """
         After loading a binary file
         args:
          ok - file loaded successfully?
        """
        pass

    # def notify_assemble(self, ea, cs, ip, use32, line):
    #     """
    #     Assemble an instruction
    #      (make sure that PR_ASSEMBLE flag is set in the processor flags)
    #      (display a warning if an error occurs)
    #      args:
    #        ea -  linear address of instruction
    #        cs -  cs of instruction
    #        ip -  ip of instruction
    #        use32 - is 32bit segment?
    #        line - line to assemble
    #     returns the opcode string
    #     """
    #     pass

    # def notify_savebase(self):
    #     """
    #     The database is being saved.
    #     Processor module should save its local data"""
    #     pass

    # def notify_out_data(self, ctx, analyze_only):
    #     """
    #     Generate text represenation of data items
    #     This function MAY change the database and create
    #     cross-references, etc.
    #     """
    #    pass

    # def notify_cmp_opnd(self, op1, op2):
    #     """
    #     Compare instruction operands.
    #     Returns 1-equal,0-not equal operands.
    #     """
    #     return False

    # def notify_can_have_type(self, op):
    #     """
    #     Can the operand have a type as offset, segment, decimal, etc.
    #     (for example, a register AX can't have a type, meaning that
    #     the user can't change its representation. see bytes.hpp for
    #     information about types and flags)
    #     Returns: bool
    #     """
    #     return True

    # def translate(self, base, offset):
    #     """
    #     Translation function for offsets
    #     Currently used in the offset display functions
    #     to calculate the referenced address
    #     Returns: ea_t
    #     """
    #     return BADADDR

    def notify_set_idp_options(self, keyword, type, value):
        """
        Set IDP-specific option
        args:
          keyword - the option name
                    or empty string (check type when 0 below)
          type    - one of
                      IDPOPT_STR  string constant
                      IDPOPT_NUM  number
                      IDPOPT_BIT  zero/one
                      IDPOPT_I64  64bit number
                      0 -> You should display a dialog to configure
                           the processor module
          value   - the actual value
        Returns:
           IDPOPT_OK        ok
           IDPOPT_BADKEY    illegal keyword
           IDPOPT_BADTYPE   illegal type of value
           IDPOPT_BADVALUE  illegal value (bad range, for example)
        otherwise return a string containing the error messages
        """
        if keyword == 'ASM_SYNTAX':
            if type != IDPOPT_STR:
                return IDPOPT_BADTYPE
            if value == 'DEC':
                self.assembler['cmnt'] = ';'
            elif value == 'BSD':
                self.assembler['cmnt'] = '//'
            else:
                return IDPOPT_BADVALUE
        return idaapi.IDPOPT_OK

    # def notify_gen_map_file(self, qfile):
    #     """
    #     Generate map file. If this function is absent then the
    #     kernel will create the map file.
    #     This function returns number of lines in output file.
    #     0 - empty file, -1 - write error
    #     """
    #     r1 = qfile.write("Line 1\n")
    #     r2 = qfile.write("Line 2\n!")
    #     return 2 # two lines

    # def notify_create_func_frame(self, func_ea):
    #     """
    #     Create a function frame for a newly created function.
    #     Set up frame size, its attributes etc.
    #     """
    #     return False

    # def notify_is_far_jump(self, icode):
    #     """
    #     Is indirect far jump or call instruction?
    #     meaningful only if the processor has 'near' and 'far' reference types
    #     """
    #     return False

    def notify_is_align_insn(self, ea):
        """
        Is the instruction created only for alignment purposes?
        Returns: number of bytes in the instruction
        """
        return 0

    def notify_out_special_item(self, ctx, segtype):
        """
        Generate text representation of an item in a special segment
        i.e. absolute symbols, externs, communal definitions etc.
        Returns: 1-overflow, 0-ok
        """
        return 0

    def notify_get_frame_retsize(self, func_ea):
        """
        Get size of function return address in bytes
        If this function is absent, the kernel will assume
             4 bytes for 32-bit function
             2 bytes otherwise
        """
        return 2

    def notify_is_switch(self, swi):
        """
        Find 'switch' idiom.
        Fills 'si' structure with information

        @return: Boolean (True if switch was found and False otherwise)
        """
        return False

    # def notify_is_sp_based(self, op):
    #     """
    #     Check whether the operand is relative to stack pointer or frame
    #     pointer.
    #     This function is used to determine how to output a stack variable
    #     This function may be absent. If it is absent, then all operands
    #     are sp based by default.
    #     Define this function only if some stack references use frame pointer
    #     instead of stack pointer.
    #     returns flags:
    #       OP_FP_BASED   operand is FP based
    #       OP_SP_BASED   operand is SP based
    #       OP_SP_ADD     operand value is added to the pointer
    #       OP_SP_SUB     operand value is substracted from the pointer
    #     """
    #     return idaapi.OP_FP_BASED

    # def notify_add_func(self, func_ea):
    #     """
    #      The kernel has added a function.
    #     @param func_ea: function start EA
    #     @return: Nothing
    #     """
    #     pass

    # def notify_del_func(self, func_ea):
    #     """
    #     The kernel is about to delete a function
    #     @param func_ea: function start EA
    #     @return: 0-ok,<0-do not delete
    #     """
    #     return 0

    # def notify_get_autocmt(self, insn):
    #     """
    #     Get instruction comment. 'insn' describes the instruction in question
    #     @return: None or the comment string
    #     """
    #     if 'cmt' in self.instruc[insn.itype]:
    #         self.instruc[insn.itype]['cmt']

    # def notify_create_switch_xrefs(self, jumpea, swi):
    #     """Create xrefs for a custom jump table
    #        @param jumpea: address of the jump insn
    #        @param swi: switch information
    #        @return: None
    #     """
    #     pass

    # def notify_calc_step_over(self, ip):
    #     """
    #     Calculate the address of the instruction which will be
    #     executed after "step over". The kernel will put a breakpoint there.
    #     If the step over is equal to step into or we can not calculate
    #     the address, return BADADDR.
    #     args:
    #       ip - instruction address
    #     returns: target or BADADDR
    #     """
    #     return idaapi.BADADDR

    # def notify_may_be_func(self, insn, state):
    #     """
    #     can a function start here?
    #     the instruction is in 'insn'
    #       arg: state -- autoanalysis phase
    #         state == 0: creating functions
    #               == 1: creating chunks
    #       returns: probability 0..100
    #     """
    #     return 0

    def notify_str2reg(self, regname):
        """
        Convert a register name to a register number
          args: regname
          Returns: register number or -1 if not avail
          The register number is the register index in the reg_names array
          Most processor modules do not need to implement this callback
          It is useful only if ph.reg_names[reg] does not provide
          the correct register names
        """
        r = self.regname2index(regname)
        if r < 0:
            return -1
        else:
            return r

    # def notify_is_sane_insn(self, insn, no_crefs):
    #     """
    #     is the instruction sane for the current file type?
    #     args: no_crefs
    #     1: the instruction has no code refs to it.
    #        ida just tries to convert unexplored bytes
    #        to an instruction (but there is no other
    #        reason to convert them into an instruction)
    #     0: the instruction is created because
    #        of some coderef, user request or another
    #        weighty reason.
    #     The instruction is in 'insn'
    #     returns: >=0-ok, <0-no, the instruction isn't
    #     likely to appear in the program
    #     """
    #     return -1

    # def notify_func_bounds(self, code, func_ea, max_func_end_ea):
    #     """
    #     find_func_bounds() finished its work
    #     The module may fine tune the function bounds
    #     args:
    #       possible code - one of FIND_FUNC_XXX (check find_func_bounds)
    #       func_ea - func start ea
    #       max_func_end_ea (from the kernel's point of view)
    #     returns: possible_return_code
    #     """
    #     return FIND_FUNC_OK

    # def asm_out_func_header(self, ctx, func_ea):
    #     """generate function header lines"""
    #     pass

    # def asm_out_func_footer(self, ctx, func_ea):
    #     """generate function footer lines"""
    #     pass

    # def asm_get_type_name(self, flag, ea_or_id):
    #     """
    #     Get name of type of item at ea or id.
    #     (i.e. one of: byte,word,dword,near,far,etc...)
    #     """
    #     if is_code(flag):
    #         pfn = get_func(ea_or_id)
    #         # return get func name
    #     elif is_word(flag):
    #         return "word"
    #     return ""

    def notify_init(self, idp_file):
        # init returns >=0 on success
        self.ovrtrans.create('$ pdp-11 overlay translations')
        return 0

    # def notify_out_label(self, ctx, label):
    #     """
    #     The kernel is going to generate an instruction label line
    #     or a function header.
    #     args:
    #       ctx - output context
    #       label - label to output
    #     If returns value <0, then the kernel should not generate the label
    #     """
    #     return 0

    # def notify_rename(self, ea, new_name):
    #     """
    #     The kernel is going to rename a byte
    #     args:
    #       ea -
    #       new_name -
    #     If returns value <0, then the kernel should not rename it
    #     """
    #     return 0

    # def notify_may_show_sreg(self, ea):
    #     """
    #     The kernel wants to display the segment registers
    #     in the messages window.
    #     args:
    #       ea
    #     if this function returns <0
    #     then the kernel will not show
    #     the segment registers.
    #     (assuming that the module have done it)
    #     """
    #     return 0

    # def notify_coagulate(self, start_ea):
    #     """
    #     Try to define some unexplored bytes
    #     This notification will be called if the
    #     kernel tried all possibilities and could
    #     not find anything more useful than to
    #     convert to array of bytes.
    #     The module can help the kernel and convert
    #     the bytes into something more useful.
    #     args:
    #       start_ea -
    #     returns: number of converted bytes
    #     """
    #     return 0

    # def notify_closebase(self):
    #     """
    #     The database will be closed now
    #     """
    #     pass

    # def notify_load_idasgn(self, short_sig_name):
    #     """
    #     FLIRT signature have been loaded for normal processing
    #     (not for recognition of startup sequences)
    #     args:
    #       short_sig_name
    #     """
    #     pass

    # def notify_auto_empty(self):
    #     """
    #     Info: all analysis queues are empty.
    #     This callback is called once when the
    #     initial analysis is finished. If the queue is
    #     not empty upon the return from this callback,
    #     it will be called later again
    #     """
    #     pass

    # def notify_is_call_insn(self, insn):
    #     """
    #     Is the instruction a "call"?
    #     args
    #       insn  - instruction
    #     returns: 0-unknown, <0-no, 1-yes
    #     """
    #     return insn.itype in (self.itype_jsr, self.itype_call)

    # def notify_is_ret_insn(self, insn, strict):
    #     """
    #     Is the instruction a "return"?
    #     insn  - instruction
    #     strict - 1: report only ret instructions
    #              0: include instructions like "leave"
    #                 which begins the function epilog
    #     returns: 0-unknown, <0-no, 1-yes
    #     """
    #     return 0

    # def notify_kernel_config_loaded(self):
    #     """
    #     This callback is called when ida.cfg is parsed
    #     """
    #     pass

    # def notify_is_alloca_probe(self, ea):
    #     """
    #     Does the function at 'ea' behave as __alloca_probe?
    #     args:
    #       ea
    #     returns: 1-yes, 0-false
    #     """
    #     return 0

    # def notify_gen_src_file_lnnum(self, ctx, filename, lnnum):
    #     """
    #     Callback: generate analog of
    #     #line "file.c" 123
    #     directive.
    #     args:
    #       ctx   - output context
    #       file  - source file (may be NULL)
    #       lnnum - line number
    #     returns: 1-directive has been generated
    #     """
    #     return 0

    # def notify_is_insn_table_jump(self, insn):
    #     """
    #     Callback: determine if instruction is a table jump or call
    #     If CF_JUMP bit can not describe all kinds of table
    #     jumps, please define this callback.
    #     It will be called for insns with CF_JUMP bit set.
    #     input: insn structure contains the current instruction
    #     returns: 0-yes, <0-no
    #     """
    #     return -1

    # def notify_auto_empty_finally(self):
    #     """
    #     Info: all analysis queues are empty definitively
    #     """
    #     pass

    # def notify_is_indirect_jump(self, insn):
    #     """
    #     Callback: determine if instruction is an indrect jump
    #     If CF_JUMP bit can not describe all jump types
    #     jumps, please define this callback.
    #     input: insn structure contains the current instruction
    #     returns: 0-use CF_JUMP, 1-no, 2-yes
    #     """
    #     return 0

    # def notify_determined_main(self, main_ea):
    #     """
    #     The main() function has been determined
    #     """
    #     pass

    # def notify_validate_flirt_func(self, ea, funcname):
    #     """
    #     flirt has recognized a library function
    #     this callback can be used by a plugin or proc module
    #     to intercept it and validate such a function
    #     args:
    #       start_ea
    #       funcname
    #     returns: -1-do not create a function,
    #               0-function is validated
    #     """
    #     return 0

    # def notify_set_proc_options(self, options, confidence):
    #     """
    #     called if the user specified an option string in the command line:
    #     -p<processor name>:<options>
    #     can be used for e.g. setting a processor subtype
    #     also called if option string is passed to set_processor_type()
    #     and IDC's set_processor_type()
    #     args:
    #       options
    #       confidence - 0: loader's suggestion,
    #                    1: user's decision
    #     returns: <0 - bad option string
    #     """
    #     return 0

    # def notify_creating_segm(self, start_ea, segm_name, segm_class):
    #     """
    #     A new segment is about to be created
    #     args:
    #       start_ea
    #       segm_name
    #       segm_class
    #     return >=0-ok, <0-segment should not be created
    #     """
    #     return 0

    # def notify_auto_queue_empty(self, type):
    #     """
    #     One analysis queue is empty.
    #     args:
    #       atype_t type
    #     This callback can be called many times, so
    #     only the auto_mark() functions can be used from it
    #     (other functions may work but it is not tested)
    #     """
    #     return 1

    # def notify_gen_regvar_def(self, ctx, canon, user, cmt):
    #     """
    #     generate register variable definition line
    #     args:
    #       ctx   - output context
    #       canon - canonical register name (case-insensitive)
    #       user  - user-defined register name
    #       cmt   - comment to appear near definition
    #     returns: >0-ok
    #     """
    #     return 0

    # def notify_setsgr(self, start_ea, end_ea, regnum, value, old_value, tag):
    #     """
    #     The kernel has changed a segment register value
    #     args:
    #       start_ea
    #       end_ea
    #       regnum
    #       value
    #       old_value
    #       uchar tag (SR_... values)
    #     returns: 0-ok, <0-error
    #     """
    #     return 0

    # def notify_set_compiler(self):
    #     """
    #     The kernel has changed the compiler information
    #     """
    #     pass

    # def notify_is_basic_block_end(self, insn, call_insn_stops_block):
    #     """
    #     Is the current instruction end of a basic block?
    #     This function should be defined for processors
    #     with delayed jump slots. The current instruction
    #     is stored in 'insn'
    #     args:
    #       call_insn_stops_block
    #       returns: 0-unknown, -1-no, 1-yes
    #     """
    #     return 0

    # def notify_make_code(self, insn):
    #     """
    #     An instruction is being created
    #     args:
    #       insn
    #     returns: 0-ok, <0-the kernel should stop
    #     """
    #     return 0

    # def notify_make_data(self, ea, flags, tid, size):
    #     """
    #     A data item is being created
    #     args:
    #       ea
    #       flags
    #       tid
    #       size
    #     returns: 0-ok, <0-the kernel should stop
    #     """
    #     return 0

    # def notify_moving_segm(self, start_ea, segm_name, segm_class,
    #                        to_ea, flags):
    #     """
    #     May the kernel move the segment?
    #     args:
    #       start_ea, segm_name, segm_class - segment to move
    #       to_ea   - new segment start address
    #       int flags - combination of MSF_... bits
    #     returns: 0-yes, <0-the kernel should stop
    #     """
    #     return 0

    # def notify_move_segm(self, from_ea, start_ea, segm_name, segm_class,
    #                      changed_netdelta):
    #     """
    #     A segment is moved
    #     Fix processor dependent address sensitive information
    #     args:
    #       from_ea  - old segment address
    #       start_ea, segm_name, segm_class - moved segment
    #       changed_netdelta - if ea-to-netnode mapping has been changed
    #     returns: nothing
    #     """
    #     pass

    # def notify_verify_noreturn(self, func_start_ea):
    #     """
    #     The kernel wants to set 'noreturn' flags for a function
    #     args:
    #       func_start_ea
    #     Returns: 0-ok, <0-do not set 'noreturn' flag
    #     """
    #     return 0

    # def notify_verify_sp(self, func_start_ea):
    #     """
    #     All function instructions have been analyzed
    #     Now the processor module can analyze the stack pointer
    #     for the whole function
    #     args:
    #       func_start_ea
    #     Returns: 0-ok, <0-bad stack pointer
    #     """
    #     return 0

    # def notify_renamed(self, ea, new_name, is_local_name):
    #     """
    #     The kernel has renamed a byte
    #     args:
    #       ea
    #       new_name
    #       is_local_name
    #     Returns: nothing. See also the 'rename' event
    #     """
    #     pass

    # def notify_set_func_start(self, func_start_ea, func_end_ea, new_ea):
    #     """
    #     Function chunk start address will be changed
    #     args:
    #       func_start_ea, func_end_ea
    #       new_ea
    #     Returns: 0-ok,<0-do not change
    #     """
    #     return 0

    # def notify_set_func_end(self, func_start_ea, func_end_ea, new_end_ea):
    #     """
    #     Function chunk end address will be changed
    #     args:
    #       func_start_ea, func_end_ea
    #       new_end_ea
    #     Returns: 0-ok,<0-do not change
    #     """
    #     return 0

    # def notify_treat_hindering_item(self, hindering_item_ea, new_item_flags,
    #                                 new_item_ea, new_item_length):
    #     """
    #     An item hinders creation of another item
    #     args:
    #       hindering_item_ea
    #       new_item_flags
    #       new_item_ea
    #       new_item_length
    #     Returns: 0-no reaction, <0-the kernel may delete the hindering item
    #     """
    #     return 0

    # def notify_get_operand_string(self, insn, opnum):
    #     """
    #     Request text string for operand (cli, java, ...)
    #     args:
    #       insn - the instruction
    #       opnum - the operand number; -1 means any string operand
    #     Returns: requested
    #     """
    #     return ""

    # def notify_coagulate_dref(self, from_ea, to_ea, may_define, code_ea):
    #     """
    #     data reference is being analyzed
    #     args:
    #       from_ea, to_ea, may_define, code_ea
    #     plugin may correct code_ea (e.g. for thumb mode refs,
    #     we clear the last bit)
    #     Returns: new code_ea or -1 - cancel dref analysis
    #     """
    #     return 0

    # ----------------------------------------------------------------------
    # The following callbacks are mandatory
    #

    def notify_emu(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc.
        Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        flag1 = is_forced_operand(insn.ea, 0)
        flag2 = is_forced_operand(insn.ea, 1)
        Feature = insn.get_canon_feature()
        self.flow = not (Feature & CF_STOP)
        if Feature & CF_USE1:
            self.handle_operand(insn, insn.Op1, flag1, True)
        if Feature & CF_USE2:
            self.handle_operand(insn, insn.Op2, flag2, True)
        if Feature & CF_JUMP:
            self.remember_problem(PR_JUMP, insn.ea)
        if Feature & CF_CHG1:
            self.handle_operand(insn, insn.Op1, flag1, False)
        if Feature & CF_CHG2:
            self.handle_operand(insn, insn.Op2, flag2, False)
        newEA = insn.ea + insn.size
        if insn.itype == self.itype_emt and insn.Op1.value == 0o376:
            create_byte(newEA, 2)
            newEA += 2
            add_cref(insn.ea, newEA, fl_F)
        elif (self.flow and
              not(insn.itype == self.itype_emt and insn.Op1.value == 0o350)):
            if (insn.Op1.type == o_imm and ill_imm(insn.Op1)):
                newEA += 2
            if (insn.Op2.type == o_imm and ill_imm(insn.Op2)):
                newEA += 2
            add_cref(insn.ea, newEA, fl_F)
        return 1

    def op_xrefset(self, insn, jmpa, op, isload):
        insn.create_op_data(jmpa, op)
        insn.add_dref(jmpa, op.offb, dr_R if isload else dr_W)

    def op_extxref(self, insn, jmpa, op, isload):
        if (op.phrase & 0o70) == 0o70:
            self.op_xrefset(insn, jmpa, op, isload)
        if insn.itype == self.itype_jmp:
            insn.add_cref(jmpa, op.offb, fl_JF)
        elif insn.itype in (self.itype_jsr, self.itype_call):
            insn.add_cref(jmpa, op.offb, fl_CF)
            if not func_does_return(jmpa):
                self.flow = False
        else:
            self.op_xrefset(insn, jmpa, op, isload)

    def op_t_mem(self, insn, op, isload):
        """
        op.type:
            # case o_near:       // Jcc/ [jmp/call 37/67]
            # case o_mem:        // 37/67/77
            # case o_far:
        """
        if (op.type == o_far):
            jmpa = to_ea(segval(op), addr16(op))
        else:
            jmpa = map_code_ea(insn, addr16(op), op.n)
        if op.phrase == 0:
            insn.add_cref(jmpa, op.offb, fl_JN)  # Jcc
            return
        self.op_extxref(insn, jmpa, op, isload)

    def op_t_displ(self, insn, op, is_forced, isload):
        """
        o_displ == op.type:  # 6x/7x (!67/!77)
        """
        set_immd(insn.ea)
        if (not(isload) and op.phrase == (0o60 + self.ireg_R0)
                and addr16(op) <= 1):
            self.loadR0data(insn, op, addr16(op))
        tmpa = get_offbase(insn.ea, op.n)
        if (not(is_forced) and is_off(self.emuFlg, op.n) and tmpa != BADADDR):
            jmpa = tmpa + addr16(op)
            self.op_extxref(insn, jmpa, op)

    def op_t_imm(self, insn, op):
        """
        o_imm == op.type:  # 27
        """
        if not ill_imm(op):
            set_immd(insn.ea)
            if op_adds_xrefs(get_flags(insn.ea), op.n):
                insn.add_off_drefs(op, dr_O, OOF_SIGNED)

    def op_t_number(self, insn, op):
        """
        o_number == op.type:  EMT/TRAP/MARK/SPL
        """
        if insn.itype == self.itype_emt and get_cmt(NULL, insn.ea, False) <= 0:
            tmp = insn
            tmpx = tmp.ops[op.n]
            if (tmpx.value >= 0o374 and tmpx.value <= 0o375):
                if (tmpx.value == 0o375):
                    tmp.Op2.value = self.emuR0data_hi
                else:
                    tmp.Op2.value = (emuR0 >> 8)
                tmp.Op2.type = o_imm
            cmt = get_predef_insn_cmt(tmp)
            if cmt:
                set_cmt(tmp.ea, cmt, False)

    def op_t_reg(self, insn, op):
        """
        o_reg == op.type:   # 0
        """
        if op.reg != self.ireg_R0:
            return
        if insn.Op2.type == o_void:  # one operand insn
            if insn.itype != self.itype_clr:
                self._undefall()
                return
            if is_bytecmd(insn):
                self.emuR0 &= 0xFF00
            else:
                self.emuR0 = 0
            self._undefdata()
            return
            # end of o_void
        if not(op is insn.Op2):
            return
        if insn.itype != self.itype_mov:
            if is_bytecmd(insn):
                self.emuR0 |= 0xFF
                self._undefdata()
                return
            self._undefall()
            return
        if is_bytecmd(insn):
            self._undefall()
            return
        if insn.Op1.type == o_imm:
            self.emuR0 = insn.Op1.value & 0xffff
            if self.emuR0 & 1:
                self._undefdata()
                return
            self.emuR0data = get_word(to_ea(insn.cs, self.emuR0))
        else:
            self._undefall()
            self._undefdata()

    def _undefall(self):
        self.emuR0 = 0xffff

    def _undefdata(self):
        self.emuR0data = 0xFFFF

    def op_t_phrase(self, insn, op, isload):
        if (op.phrase & 7) == self.ireg_R0:
            if (not(isload) and op.phrase == (0o10 + self.ireg_R0)):
                self.loadR0data(insn, op, 0)
            elif (insn.Op2.type == o_void or op is insn.Op2):
                self._undefall()

    def _undefbyte(self, sme):
        if not sme:
            self.emuR0data |= 0xFF
        else:
            self.emuR0data |= 0xFF00

    def loadR0data(self, insn, op, sme):
        if insn.Op2.type == o_void:
            if insn.itype != self.itype_clr:
                self._undefdata()
                return
            if sme:
                if not is_bytecmd(insn):
                    self._undefdata()
                    return
                self.emuR0data &= 0xFF
                return
            if is_bytecmd(insn):
                self.emuR0data &= 0xFF00
            else:
                self.emuR0data = 0
            return
        # FIXME compare instructions by address
        # if ( x != &insn.Op2 )
        if op is not insn.Op2:
            return
        if insn.Op1.type == o_imm:
            if insn.itype == self.itype_mov:
                if not is_bytecmd(insn.bytecmd):
                    if sme:
                        self._undefdata()
                        return
                    self.emuR0data = insn.Op1.value & 0xFFFF
                    return
                if not sme:
                    self.emuR0data |= insn.Op1.value & 0xff
                else:
                    self.emuR0data |= (nsn.Op1.value & 0xff) << 8
                return
            if is_bytecmd(insn):
                self._undefdata()
                return
            if not sme:
                self.emuR0data |= 0x00FF
            else:
                self.emuR0data |= 0xFF00
            return
        # end of == o_imm
        if is_bytecmd(insn):
            self._undefbyte(sme)
        else:
            self._undefdata()

    def handle_operand(self, insn, op, is_forced, isload):
        """
        """
        if op.type in [o_near, o_mem, o_far]:
            self.op_t_mem(insn, op, isload)
            return
        elif o_displ == op.type:  # 6x/7x (!67/!77)
            self.op_t_displ(insn, op, is_forced, isload)
            return
        elif o_imm == op.type:  # 27
            self.op_t_imm(insn, op)
            return
        elif o_number == op.type:  # EMT/TRAP/MARK/SPL
            self.op_t_number(insn, op)
            return
        elif o_reg == op.type:  # 0
            self.op_t_reg(insn, op)
            return
        elif o_phrase == op.type:  # 1x/2x/3x/4x/5x (!27/!37)
            self.op_t_phrase(insn, op, isload)
            return
        elif o_fpreg == op.type:  # FPP
            # nothing to do
            return
        else:
            warning("%" + FMT_EA + "o (%s): bad optype %s" %
                    (insn.ip, insn.get_canon_mnem(), op.type))
        return

    def _out_o_imm(self, ctx, op):
        if ill_imm(op):
            ctx.out_line("(PC)+")
        else:
            ctx.out_symbol(self.assembler['imm'])  # '#' - DEC, '$' - BSD
            if op.dtype in (dt_float, dt_double):
                # ctx.out_symbol('^')
                # ctx.out_symbol('F')
                # print_fpval(str, sizeof(str), &x.value, 2)
                ctx.out_line("^F%f" % op.value, COLOR_NUMBER)
            else:
                ctx.out_value(op, OOF_SIGNED | OOFW_IMM)

    def _out_o_mem(self, ctx, op):
        if op.phrase != 0:
            if op.phrase in (0o37, 0o77):
                ctx.out_symbol('@')
            if op.phrase == 0o37:
                ctx.out_symbol(self.assembler['imm'])  # '#' - DEC, '$' - BSD
                if addr16(op) < self.ml.asect_top and not(is_off(F, op.n)):
                    ctx.out_value(op, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN |
                                  OOFW_16)
                    return
        if op.type == o_far:
            segadr = to_ea(op.segval, addr16(op))
        else:
            segadr = map_code_ea(ctx.insn, addr16(op), op.n)
        if not ctx.out_name_expr(op, segadr, addr16(op)):
            if op.type == o_far or addr16(op) < 0o160000:
                remember_problem(PR_NONAME, ctx.insn.ea)
            ctx.out_value(op, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_16)

    def _out_o_phrase(self, ctx, op):
        """
        case o_phrase:   # 1x/2x/3x/4x/5x (!27/!37)
        """
        ph = op.phrase >> 3
        rn = self.reg_names[op.phrase & 7]
        if 1 == ph:
            # DEC: @%s,  BSD: (%s)
            fmt = self.assembler.get('ph1_fmt', '@%s')
            ctx.out_line(fmt % rn)
        elif 2 == ph:
            ctx.out_line("(%s)+" % rn)
        elif 3 == ph:
            fmt = self.assembler.get('ph3_fmt', '@(%s)+')
            ctx.out_line(fmt % rn)
        elif 4 == ph:
            ctx.out_line("-(%s)" % rn)
        elif 5 == ph:
            fmt = self.assembler.get('ph5_fmt', '@-(%s)')
            ctx.out_line(fmt % rn)
        else:
            warning("out: %" + FMT_EA + "o: bad optype %d" %
                    (ctx.insn.ip, op.type))

    def out_reg(self, ctx, ridx):
        """
        Output register operand name
        """
        ctx.out_register(self.reg_names[ridx])

    def notify_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with
        init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate
        the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        if o_void == op.type:
            return False
        elif o_reg == op.type:
            ctx.out_register(self.reg_names[op.reg])
        elif o_fpreg == op.type:
            ctx.out_register(self.reg_names[op.reg + 8])
        elif o_imm == op.type:  # 0o27
            self._out_o_imm(ctx, op)
        elif op.type in (o_mem, o_near, o_far):
            self._out_o_mem(ctx, op)
        elif o_number == op.type:  # EMT/TRAP/MARK/SPL
            ctx.out_value(op, OOF_NUMBER | OOFS_NOSIGN | OOFW_8)
        elif o_displ == op.type:
            if op.phrase >= 0o70:
                ctx.out_symbol('@')
            ctx.out_value(op, OOF_ADDR | OOF_SIGNED | OOFW_16)
            ctx.out_line("(%s)" % self.reg_names[op.phrase & 7])
        elif o_phrase == op.type:  # 1x/2x/3x/4x/5x (!27/!37)
            self._out_o_phrase(ctx, op)
        else:
            warning("out: %" + FMT_EA + "o: bad optype %d" %
                    (ctx.insn.ip, op.type))
        return True

    def out_mnem(self, ctx):
        """
        Generate the instruction mnemonics
        """

        postfix = ""
        if is_bytecmd(ctx.insn):
            postfix = "b"
        ctx.out_mnem(8, postfix)

    def notify_out_insn(self, ctx):
        """
        Generate text representation of an instruction in 'ctx.insn'
        structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        ctx.out_mnemonic()
        if ctx.insn.itype == self.itype_compcc:
            i = 0
            first = 0
            tabcc = [
                self.itype_clc, self.itype_clv, self.itype_clz, self.itype_cln,
                self.itype_sec, self.itype_sev, self.itype_sez, self.itype_sen
            ]
            code = ctx.insn.Op1.phrase
            ctx.out_symbol('<')
            if code >= 0o20:
                code ^= 0o20
                if code == 0:
                    ctx.out_line(COLSTR("nop!^O20", SCOLOR_INSN))
                i = 4
            while code:
                if code & 1:
                    if first:
                        ctx.out_symbol('!')
                    first += 1
                    mnem = self.instruc[tabcc[i]]['name']
                    ctx.out_line(mnem, COLOR_INSN)
                i += 1
                code >>= 1
            ctx.out_symbol('>')
        ctx.out_one_operand(0)
        if ctx.insn.Op2.type != o_void:
            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(1)
        ctx.out_immchar_cmts()
        ctx.flush_outbuf()

    def jmpoper(self, insn, op, nibble0):
        """
        Handle jump operand
        """
        self.loadoper(insn, op, nibble0)
        if op.type == o_mem and op.phrase != 0o77:
            op.type = o_near
        # FIXME ml & ovrtrans !!!
        if (op.type == o_near and addr16(op) >= self.ml.ovrcallbeg
                and addr16(op) <= self.ml.ovrcallend):
            trans = self.ovrtrans.altval(addr16(op))
            # msg("addr=%o, trans=%lo\n", op.addr16, trans);
            if trans != 0:
                S = getseg(trans)
                if S != NULL:
                    op.type = o_far
                    # .segval
                    op.specval = S.sel
                    # op.addr16 is op.addr_shorts.low
                    # op.segval is op.specval_shorts.low
                    a = (trans - to_ea(op.specval & 0xffff, 0))
                    op.addr = a & 0xffff

    def loadoper(self, insn, op, nibble):
        if nibble == 0o27:
            F1 = get_flags(insn.ea)
            F2 = get_flags(insn.ea+insn.size)
            op.type = o_imm
            if is_head(F1):
                # .ill_imm
                op.specflag1 = 0 if is_tail(F2) else 1
            else:
                # .ill_imm
                op.specflag1 = is_head(F2)
            op.offb = insn.size & 0xff
            op.value = insn.get_next_word()
        elif nibble in (0o37, 0o77, 0o67):
            op.type = o_mem
            op.offb = insn.size & 0xff
            base = insn.get_next_word()
            op.phrase = nibble
            if nibble != 0o37:
                base += (insn.ip + insn.size) & 0xffff
            # op.addr16 is op.addr_shorts.low
            op.addr = base & 0xffff
        else:
            if (nibble & 0o70) == 0:
                op.type = o_reg
                op.reg = nibble
            else:
                op.phrase = nibble
                if nibble < 0o60:
                    op.type = o_phrase
                else:
                    op.type = o_displ
                    op.offb = insn.size & 0xff
                    op.addr = insn.get_next_word() & 0xffff

    def ana_017000(self, insn, nibble0):
        if nibble0 == 0:
            insn.itype = self.itype_cfcc
        elif nibble0 == 1:
            insn.itype = self.itype_setf
        elif nibble0 == 2:
            insn.itype = self.itype_seti
        elif nibble0 == 0o11:
            insn.itype = self.itype_setd
        elif nibble0 == 0o12:
            insn.itype = self.itype_setl
        else:
            raise InvalidInsnError()

    def ana_fpcom1(self, insn, nibble1):
        """
        analize fpcom1 insn
        """
        fpcom1 = [
            self.itype_ldfps, self.itype_stfps, self.itype_stst,
            self.itype_clrd, self.itype_tstd, self.itype_absd,
            self.itype_negd
        ]
        if nibble1 >= 4:
            insn.Op1.dtype = insn.Op2.dtype = dt_double
            if insn.Op1.type == o_reg:
                insn.Op1.type = o_fpreg
        if not ((nibble1-1) >= 0 and nibble1-1 < len(fpcom1)):
            raise InvalidInsnError()
        insn.itype = fpcom1[nibble1-1]

    def ana_fpcom2(self, insn, nibble1):
        """
        analize fpcom2 insn
        """
        fpcom2 = [
            self.itype_muld, self.itype_modd, self.itype_addd,
            self.itype_ldd, self.itype_subd, self.itype_cmpd,
            self.itype_std, self.itype_divd, self.itype_stexp,
            self.itype_stcdi, self.itype_stcdf, self.itype_ldexp,
            self.itype_ldcid, self.itype_ldcfd
        ]
        insn.Op2.type = o_fpreg
        insn.Op2.reg = (nibble1 & 3)
        insn.Op2.dtype = dt_double
        idx = (nibble1 >> 2) - 2
        if not (idx >= 0 and idx < len(fpcom2)):
            raise InvalidInsnError()
        insn.itype = fpcom2[idx]
        if insn.itype not in (self.itype_ldexp, self.itype_stexp):
            if insn.Op1.type == o_reg:
                insn.Op1.type = o_fpreg
            if insn.itype not in (self.itype_stcdi, self.itype_ldcid):
                insn.Op1.dtype = dt_double
        if insn.itype in (self.itype_std, self.itype_stexp,
                          self.itype_stcdi, self.itype_stcdf):
            temp = insn.Op2
            self.copy_ins_op(insn.Op2, insn.Op1)
            self.copy_ins_op(insn.Op1, temp)
            insn.Op1.n = 0
            insn.Op2.n = 1

    def copy_ins_op(self, dst_op, src_op):
        """
        copy attributes of `src_op` to `dst_op`
        """
        dst_op.reg = src_op.reg
        dst_op.type = src_op.type
        dst_op.dtype = src_op.dtype
        dst_op.value = src_op.value
        dst_op.offb = src_op.offb
        dst_op.addr = src_op.addr
        dst_op.specval = src_op.specval
        # dst_op.opname = src_op.opname
        # dst_op.details = src_op.details

    def ana_ficom(self, insn, nibble0):
        """
        Analyze FICOM insns
        """
        if self.cpu_1801bm1:
            raise InvalidInsnError()
        ficom = [self.itype_fadd, self.itype_fsub, self.itype_fmul,
                 self.itype_fdiv]
        insn.Op1.type = o_reg
        insn.Op1.reg = nibble0 & 7
        insn.itype = ficom[nibble0 >> 3]

    def ana_sob(self, insn, nibble0, nibble1):
        """
        analize SOB insn
        """
        insn.itype = self.itype_sob
        insn.Op1.type = o_reg
        insn.Op1.reg = nibble1 & 7
        insn.Op2.type = o_near
        insn.Op2.phrase = 0
        # .addr16
        insn.Op2.addr = (insn.ip + 2 - (2 * nibble0)) & 0xffff

    def ana_eis(self, insn, nibble0, nibble1):
        """
        analize EIS

        1. 1801BM1 supports XOR
        2. 1801BM1a doesn't support MUL, but BM1g -- does
           at this moment I assume 1801BM1 is 1801BM1a
        """
        nib1swt = nibble1 >> 3
        eiscom = [self.itype_mul, self.itype_div, self.itype_ash,
                  self.itype_ashc, self.itype_xor]
        cmd = eiscom[nib1swt]
        if self.cpu_1801bm1 and cmd != self.itype_xor:
            raise InvalidInsnError()
        if cmd == self.itype_xor:
            # XOR  R, Dst  where R is Op1, Dst is Op2
            insn.Op1.type = o_reg
            insn.Op1.reg = nibble1 & 7
            self.loadoper(insn, insn.Op2, nibble0)
        else:
            # CMD  R, Src  where R is Op1, Src is Op2
            insn.Op2.type = o_reg
            insn.Op2.reg = nibble1 & 7
            self.loadoper(insn, insn.Op1, nibble0)
        insn.itype = cmd

    def ana_nib2_007(self, insn, nibble0, nibble1):
        """
        Analyze nibble2 == 0o7
        """
        nib1swt = nibble1 >> 3
        if nib1swt == 6:  # CIS
            raise InvalidInsnError()
        elif nib1swt == 5:  # FIS
            if nibble1 != 0o50 or nibble0 >= 0o40:
                raise InvalidInsnError()
            self.ana_ficom(insn, nibble0)
        elif nib1swt == 7:  # SOB
            self.ana_sob(insn, nibble0, nibble1)
        else:
            self.ana_eis(insn, nibble0, nibble1)

    def ana_nib2_000(self, insn, nibble0, nibble1):
        """
        Analyze nibble2 == 000
        """
        if nibble1 >= 0o70:
            raise InvalidInsnError()
        if nibble1 > 0o64:
            mt2cmd = [self.itype_mfpi, self.itype_mtpi, self.itype_sxt]
            insn.itype = mt2cmd[nibble1 - 0o65]
            self.loadoper(insn, insn.Op1, nibble0)
            return
        if nibble1 == 0o64:
            insn.itype = self.itype_mark
            insn.Op1.type = o_number
            insn.Op1.value = nibble0
            return
        if nibble1 >= 0o50:
            self.oneoper(insn, nibble0, nibble1)
            return
        if nibble1 >= 0o40:
            if (nibble1 & 7) == 7:
                insn.itype = self.itype_call
                # insn.itype = self.itype_jsr
                # insn.Op1.type = o_reg
                # insn.Op1.reg = nibble1 & 7
                self.jmpoper(insn, insn.Op1, nibble0)
            else:
                insn.itype = self.itype_jsr
                insn.Op1.type = o_reg
                insn.Op1.reg = nibble1 & 7
                self.jmpoper(insn, insn.Op2, nibble0)
            return
        # switch ( nibble1 )
        # {
        if 3 == nibble1:
            insn.itype = self.itype_swab
            self.loadoper(insn, insn.Op1, nibble0)
            return
        elif 1 == nibble1:
            insn.itype = self.itype_jmp
            self.jmpoper(insn, insn.Op1, nibble0)
            return
        elif 2 == nibble1:  # 0o0002xx
            if nibble0 == 7:  # 0o000207
                insn.itype = self.itype_return
                # insn.itype = self.itype_rts
                # insn.Op1.type = o_reg
                # insn.Op1.reg = nibble0
                return
            if nibble0 < 7:  # 0o00020x  x<7: rts Rx
                insn.itype = self.itype_rts
                insn.Op1.type = o_reg
                insn.Op1.reg = nibble0
                return
            if nibble0 < 0o30:
                raise InvalidInsnError()
            if nibble0 < 0o40:
                insn.itype = self.itype_spl
                insn.Op1.value = nibble0 & 7
                insn.Op1.type = o_number
                return
            v = nibble0 & 0o37
            if 0o00 == v: insn.itype = self.itype_nop
            elif 0o01 == v: insn.itype = self.itype_clc
            elif 0o02 == v: insn.itype = self.itype_clv
            elif 0o04 == v: insn.itype = self.itype_clz
            elif 0o10 == v: insn.itype = self.itype_cln
            elif 0o17 == v: insn.itype = self.itype_ccc
            elif 0o21 == v: insn.itype = self.itype_sec
            elif 0o22 == v: insn.itype = self.itype_sev
            elif 0o24 == v: insn.itype = self.itype_sez
            elif 0o30 == v: insn.itype = self.itype_sen
            elif 0o37 == v: insn.itype = self.itype_scc
            else:
                insn.itype = self.itype_compcc
                insn.Op1.phrase = v
            return
        elif 0 == nibble1:
            if nibble0 <= 7:
                # generic PDP-11
                misc0 = [
                    self.itype_halt, self.itype_wait, self.itype_rti,
                    self.itype_bpt, self.itype_iot, self.itype_reset,
                    self.itype_rtt, self.itype_mfpt
                ]
                insn.itype = misc0[nibble0]
                return
            if nibble0 < 0o20 and (self.cpu_1801bm1 or self.cpu_1801bm2):
                # 1801BM1/BM2 specific: START and STEP
                if (nibble0 & 0o14) == 0o10:
                    insn.itype = self.itype_start
                else:  # elif (nibble0 & 0o14) == 0o14:
                    insn.itype = self.itype_step
                return
            elif self.cpu_1801bm2 and nibble0 <= 0o37:
                # https://zx-pk.ru/threads/17284-km1801vm2-tekhnicheskoe-opisanie/page5.html
                # https://github.com/nzeemin/bkbtl-doc/wiki/1801vm1-vs-1801vm2-ru
                insn.itype = self.bm2_cmd.get(nibble0, 0)
                if not insn.itype:
                    raise InvalidInsnError()
            else:
                raise InvalidInsnError()
            return
        else:  # >=4
            lcc2com = [
                self.itype_br, self.itype_bne, self.itype_beq, self.itype_bge,
                self.itype_blt, self.itype_bgt, self.itype_ble
            ]
            insn.itype = lcc2com[(nibble1 >> 2) - 1]
            self.condoper(insn)
        # }
        return

    def oneoper(self, insn, nibble0, nibble1):
        """
        handle one operand insn
        """
        self.loadoper(insn, insn.Op1, nibble0)
        onecmd = [
            self.itype_clr, self.itype_com, self.itype_inc, self.itype_dec,
            self.itype_neg, self.itype_adc, self.itype_sbc, self.itype_tst,
            self.itype_ror, self.itype_rol, self.itype_asr, self.itype_asl
        ]
        insn.itype = onecmd[nibble1 - 0o50]

    def ana_nib2_010(self, insn, nibble0, nibble1):
        """
        Analyze nibble2 == 0o10
        """
        if nibble1 >= 0o70:
            raise InvalidInsnError()
        # nib1swt = nibble1 >> 3
        if nibble1 >= 0o64:
            mt1cmd = [self.itype_mtps, self.itype_mfpd,
                      self.itype_mtpd, self.itype_mfps]
            insn.itype = mt1cmd[nibble1 - 0o64]
            self.loadoper(insn, insn.Op1, nibble0)
            return
        if nibble1 >= 0o50:
            set_bytecmd(insn)
            # oneoper:
            self.oneoper(insn, nibble0, nibble1)
            return
        if nibble1 >= 0o40:
            insn.Op1.type = o_number  # EMT/TRAP
            insn.Op1.value = self._code & 0o377
            if nibble1 >= 0o44:
                insn.itype = self.itype_trap
            else:
                insn.itype = self.itype_emt
            return
        cc2com = [
            self.itype_bpl, self.itype_bmi, self.itype_bhi, self.itype_blos,
            self.itype_bvc, self.itype_bvs, self.itype_bcc, self.itype_bcs
        ]
        insn.itype = cc2com[nibble1 >> 2]
        # condoper:
        self.condoper(insn)
        return

    def condoper(self, insn):
        """
        handle conditional operand
        """
        insn.Op1.type = o_near
        insn.Op1.phrase = 0
        offs = self._code & 0x7f
        # offs is signed
        n_ip = insn.ip + insn.size
        if (self._code & 0x80) == 0x80:  #
            insn.Op1.addr = (n_ip - 2 * (0x80 - offs)) & 0xffff
        else:
            insn.Op1.addr = (n_ip + 2 * offs) & 0xffff

    def ana_nib2_017(self, insn, nibble0, nibble1):
        """
        Analyze nibble2 == 0o17
        """
        nib1swt = nibble1 >> 3
        if nibble1 == 0:
            self.ana_017000(insn, nibble0)
            return
        self.loadoper(insn, insn.Op1, nibble0)
        if nib1swt != 0:
            self.ana_fpcom2(insn, nibble1)
        else:
            self.ana_fpcom1(insn, nibble1)

    def ana_add(self, insn, nibble0, nibble1):
        insn.itype = self.itype_add
        self.loadoper(insn, insn.Op1, nibble1)
        self.loadoper(insn, insn.Op2, nibble0)

    def ana_sub(self, insn, nibble0, nibble1):
        insn.itype = self.itype_sub
        self.loadoper(insn, insn.Op1, nibble1)
        self.loadoper(insn, insn.Op2, nibble0)

    def ana_twoopcmd(self, insn, nibble0, nibble1, nibble2):
        twoop = [self.itype_mov, self.itype_cmp, self.itype_bit,
                 self.itype_bic, self.itype_bis]
        insn.itype = twoop[(nibble2 & 7) - 1]
        if (nibble2 & 0o10) != 0:
            set_bytecmd(insn)
        else:
            set_wordcmd(insn)
        self.loadoper(insn, insn.Op1, nibble1)
        self.loadoper(insn, insn.Op2, nibble0)

    def notify_ana(self, insn):
        """
        Decodes an instruction into insn
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        if (insn.ea & 1) != 0:
            return 0
        insn.Op1.dtype = insn.Op2.dtype = dt_word
        self._code = insn.get_next_word()
        nibble0 = (self._code & 0o77)
        nibble1 = (self._code >> 6) & 0o77
        nibble2 = (self._code >> 12) & 0o17
        try:
            if nibble2 == 0o17:
                self.ana_nib2_017(insn, nibble0, nibble1)
            elif nibble2 == 7:
                self.ana_nib2_007(insn, nibble0, nibble1)
            elif nibble2 == 0o10:
                self.ana_nib2_010(insn, nibble0, nibble1)
            elif nibble2 == 0:
                self.ana_nib2_000(insn, nibble0, nibble1)
            elif nibble2 == 0o16:
                self.ana_sub(insn, nibble0, nibble1)
            elif nibble2 == 0o6:
                self.ana_add(insn, nibble0, nibble1)
            else:
                # two ops command
                self.ana_twoopcmd(insn, nibble0, nibble1, nibble2)
        except InvalidInsnError:
            return 0
        if is_bytecmd(insn):
            self.handle_byte_op(insn.Op1)
            self.handle_byte_op(insn.Op2)
        if insn.Op1.type == o_imm and ill_imm(insn.Op1):
            insn.size -= 2
        if insn.Op2.type == o_imm and ill_imm(insn.Op2):
            insn.size -= 2
        # Return decoded instruction size or zero
        return insn.size

    def handle_byte_op(self, op):
        """
        handle an operand for byte comand
        """
        if ((op.type == o_mem and op.phrase != 0o77) or
                (op.type == o_displ and (op.phrase & 0o70) == 0o60)):
            op.dtype = dt_byte

    # ----------------------------------------------------------------------
    def init_instructions(self):
        for i, v in enumerate(self.instruc):
            n = v['name']
            if not n:
                setattr(self, 'itype_null', i)
            elif n == '.word':
                setattr(self, 'itype_compcc', i)
            else:
                setattr(self, 'itype_' + n, i)

        # Icode of return instruction. It is ok to give any of possible return
        # instructions
        # self.icode_return = self.itype_return
        self.icode_return = self.itype_rts
        self.bm2_cmd.update({
            0o20: self.itype_rsel, 0o21: self.itype_mfus,
            0o22: self.itype_rcpc, 0o24: self.itype_rcps,
            0o31: self.itype_mtus,
            0o32: self.itype_wcpc, 0o34: self.itype_wcps
        })
        self.bm1_cmd.update({
            0o12: self.itype_start,
            0o16: self.itype_step
        })

    def init_registers(self):
        for i, r in enumerate(self.reg_names):
            setattr(self, 'ireg_%s' % r, i)

    def regname2index(self, regname):
        try:
            return getattr(self, 'ireg_%s' % regname)
        except Exception:
            return -1

    def emuR0data_hi(self):
        return (self.emuR0data >> 8) & 0xff

    def emuR0data_lo(self):
        return self.emuR0data & 0xff

    @property
    def cpu_1801bm1(self):
        return self._cpu == CPU_1801BM1

    @property
    def cpu_1801bm2(self):
        return self._cpu == CPU_1801BM2

    # ----------------------------------------------------------------------
    def __init__(self):
        """
        Initialize processor instance
        """
        processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()
        self._code = None  # current insn code (16bit word) in ana()
        self.flow = None
        self.emuFlg = False
        self.emuR0 = 0xffff
        self.emuR0data = 0xffff
        self.ovrtrans = netnode()
        self._cpu = 0


# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    return k1801bm1_processor_t()
