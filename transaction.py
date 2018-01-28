from enum import Enum

from Crypto.Hash import SHA256
import ecdsa

DATUM_SEP       = 0xaa
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
    return sectionType(byte)

# A datum is an n-element list of 32-byte values.
# TODO: Allow data of less than 32 bytes
class Datum:
    def __init__(self, dx):
        self.dx = dx

    def dx_to_bytes(self):
        running_bytes = bytearray([])
        for i in self.dx:
            running_bytes += bytearray([DATUM_SEP]) + i
        return running_bytes

class Section:
    def __init__(self, sx_type, sx_data):
        self.type = sx_type
        self.data = sx_data

    def data_to_bytes(self):
        running_bytes = bytearray([])
        for i in self.data:
            running_bytes += i.dx_to_bytes()
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

# Take a byte array and return a transaction object
def bytes_to_tx(txbytes):
    curr_byte = txbytes[0]

    running_tx = Transaction([])

    if(curr_byte != TX_BEGIN):
        # Throw an error
        print("Error: invalid transaction ", txbytes)
    i = 1
    while txbytes[i] != TX_END:
        # Get transaction section type
        sx = Section(byte_to_st(txbytes[i]), [])
        i += 1

        while txbytes[i] != DATA_END:
            if(txbytes[i] == DATUM_SEP):
                # Read 32 bytes
                datum_bytes = txbytes[i+1:i+33]
                sx.data += [Datum([datum_bytes])]
                i += 33
        i += 1

        running_tx.sections += [sx]
    return running_tx

# Take a transaction as argument, return a bool indicating its validity.
def transaction_is_valid(tx):
    print("Placeholder")

# Simple test vector
# TODO: Write actual test cases for this

d = Datum([b'ffffffffffffffffffffffffffffffff', b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"])
s = Section(sectionType.BURN, [d])
t = Transaction([s])


print(t.tx_to_bytes())
print(bytes_to_tx(t.tx_to_bytes()).tx_to_bytes())
print(t)

print("\n\n", byte_to_st(0x01))


d1 = Datum([b'ffffffffffffffffffffffffffffffff', b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"])
s1 = Section(sectionType.PAINT_INPUTS, [d])
d2 = Datum([b'ffffffffffffffffffffffffffffffff', b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"])
s2 = Section(sectionType.PAINT_OUTPUTS, [d])
t2 = Transaction([s1, s2])


print(t2.tx_to_bytes())
print(bytes_to_tx(t2.tx_to_bytes()).tx_to_bytes())
print(t)

print(t2.strip_section(sectionType.PAINT_INPUTS).tx_to_bytes())

print("\n\n", byte_to_st(0x01))
