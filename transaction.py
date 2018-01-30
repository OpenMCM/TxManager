from enum import Enum

from Crypto.Hash import SHA256
import ecdsa

DATUM_SQUIRT    = 0x04  # Indicator of a 4-byte value in a tuple
DATUM_INCHWORM  = 0x08  # Indicator of an 8-byte value in a tuple
DATUM_SHORT     = 0x10  # Indicator of a 16-byte value in a tuple
DATUM_INT       = 0x20  # Indicator of a 32-byte value in a tuple
DATUM_LONG      = 0x40  # Indicator of a 64-byte value in a tuple
DATUM_SEP       = 0xaa  # Separator between n-tuples of data

DATUM_INDICATORS = frozenset((DATUM_SQUIRT, DATUM_INCHWORM,
                              DATUM_SHORT, DATUM_INT, DATUM_LONG))

DATA_END        = 0x7f
TX_BEGIN        = 0xff
TX_END          = 0x00

class sectionType(Enum):
    INPUTS = 1
    OUTPUTS = 2
    WILDCARD_INPUTS = 3
    WILDCARD_OUTPUTS = 4
    SIGNATURES = 5
    WILDCARD_CHANGE = 6
    WILDCARD_ID = 7
    WILDCARD_SIGNATURES = 8
    COINCOLOR = 9
    MINT_PAINT = 10
    AUTHED_MINTERS = 11
    DEAUTHER_MINTERS = 12
    NONCE = 13
    PAINT_INPUTS = 14
    PAINT_OUTPUTS = 15
    MINT_OUTPUTS = 16
    BURN = 17

def st_to_bytes(type):
    for i in range(1, 18):
        if(i == type.value):
            return bytearray([i])
    return bytearray([0x00])

def byte_to_st(byte):
    if(byte > 17):
        return -1
    return sectionType(byte)

# A datum is an n-element list of 32-byte values.
# TODO: Allow data of less than 32 bytes
class Datum:
    def __init__(self, dx):
        self.dx = dx

    def dx_to_bytes(self):
        running_bytes = bytearray([])
        for i in self.dx:
            if(len(i) == 4):
                running_bytes += bytearray([DATUM_SQUIRT]) + i
            elif(len(i) == 8):
                running_bytes += bytearray([DATUM_INCHWORM]) + i
            elif(len(i) == 16):
                running_bytes += bytearray([DATUM_SHORT]) + i
            elif(len(i) == 32):
                running_bytes += bytearray([DATUM_INT]) + i
            elif(len(i) == 64):
                running_bytes += bytearray([DATUM_LONG]) + i
        return running_bytes

class Section:
    def __init__(self, sx_type, sx_data):
        self.type = sx_type
        self.data = sx_data

    def data_to_bytes(self):
        running_bytes = bytearray([])
        for i in self.data:
            running_bytes += bytearray([DATUM_SEP]) + i.dx_to_bytes()
        return running_bytes

    def sx_to_bytes(self):
        return st_to_bytes(self.type) + self.data_to_bytes() + bytearray([DATA_END])

class Transaction:
    def __init__(self, sxs):
        self.sections = sxs

    def sections_to_bytes(self):
        running_bytes = bytearray([])
        for i in self.sections:
            running_bytes += i.sx_to_bytes()
        return running_bytes

    def tx_to_bytes(self):
        return bytearray([TX_BEGIN]) + self.sections_to_bytes() + bytearray([TX_END])

    # Returns a new transaction that excludes the section of sx_type
    def strip_section(self, sx_type):
        new_sections = [i for i in self.sections if i.type != sx_type]
        return Transaction(new_sections)

    def get_section(self, sx_type):
        for sx in sections:
            # Possible error: what if sx_type is invalid?
            if(sx.type == sx_type):
                return sx

def bytes_to_tx(txbytes):
    # Returns (int, Datum)
    def read_datum(index, txbytes):
        i = index

        datum = []

        while(txbytes[i] in DATUM_INDICATORS):
            word_size = txbytes[i]
            i += 1
            # We assume here that the respective value in DATUM_INDICATORS
            # represents the size of the data we're reading. PLEASE DON'T
            # VIOLATE THIS it makes my life so easy thnx
            doot = txbytes[i : i + word_size]
            i += word_size
            datum += [doot]

        return (i, Datum(datum))

    # Returns (int, [Datum])
    def read_data(index, txbytes):
        i = index

        data = []

        while(txbytes[i] == DATUM_SEP):
            i += 1
            i, datum = read_datum(i, txbytes)
            data += [datum]

        return (i, data)

    # Returns (int, section)
    def read_section(index, txbytes, secType):
        i = index

        i, secData = read_data(i, txbytes)
        return (i, Section(secType, secData))

    # Returns (int, [section])
    def read_sections(index, txbytes):
        i = index
        sections = []
        while(txbytes[i] != TX_END):
            st = byte_to_st(txbytes[i])
            i += 1
            i, intersections = read_section(i, txbytes, st)
            sections += [intersections]
            i += 1

        return (i, sections)
    i = 0
    curr_byte = txbytes[i]
    i += 1

    if(curr_byte != TX_BEGIN):
        # Throw an error
        print("Error: invalid transaction ", txbytes)
    i, sections = read_sections(i, txbytes)

    return Transaction(sections)


# Take a transaction as argument, return a bool indicating its validity.
def transaction_is_valid(tx):
    # Alright, so we need a 'for' loop to iterate through the sections

    # If we come across a signature, hash the catted bytes of all previous
    # Sections and assert that it matches the first data point in

    # Preliminary version: Only works with non-wildcard shuffles
    for i in tx.sections:
        print(i.type)
    print("Placeholder")

# Simple test vector
# TODO: Write actual test cases for this

d = Datum([b'ffffffffffffffffffffffffffffffff', b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"])
dp = Datum([b'gggggggggggggggggggggggggggggggg'])
s = Section(sectionType.BURN, [d, dp])
t = Transaction([s])

print("Not decoded:")
print(t.tx_to_bytes())
print("Decoded:")
print(bytes_to_tx(t.tx_to_bytes()).tx_to_bytes())


d1 = Datum([b'ffffffffffffffffffffffffffffffff', b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"])
s1 = Section(sectionType.PAINT_INPUTS, [d1])
d2 = Datum([b'ffffffffffffffffffffffffffffffff', b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"])
s2 = Section(sectionType.PAINT_OUTPUTS, [d1, d2])
t2 = Transaction([s1, s2])

print("Not decoded: ")
print(t2.tx_to_bytes())
print("Decoded:")
print(bytes_to_tx(t2.tx_to_bytes()).tx_to_bytes())
print(t)

print(t2.strip_section(sectionType.PAINT_INPUTS).tx_to_bytes())

print("\n\n", byte_to_st(0x01))
