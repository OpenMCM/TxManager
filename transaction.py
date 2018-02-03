from enum import Enum

from Crypto.Hash import SHA256
import ecdsa

DATUM_BYTE      = 0x01  # Indicator of a 1-byte value in a tuple
DATUM_SQUIRT    = 0x04  # Indicator of a 4-byte value in a tuple
DATUM_INCHWORM  = 0x08  # Indicator of an 8-byte value in a tuple
DATUM_SHORT     = 0x10  # Indicator of a 16-byte value in a tuple
DATUM_INT       = 0x20  # Indicator of a 32-byte value in a tuple
DATUM_LONG      = 0x40  # Indicator of a 64-byte value in a tuple
DATUM_SEP       = 0xaa  # Separator between n-tuples of data

DATUM_INDICATORS = frozenset((DATUM_BYTE, DATUM_SQUIRT, DATUM_INCHWORM,
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
    DEAUTHED_MINTERS = 12
    NONCE = 13
    PAINT_INPUTS = 14
    PAINT_OUTPUTS = 15
    MINT_OUTPUTS = 16
    SIG_MINT = 17
    SIG_PAINT = 18

def st_to_bytes(type):
    for i in range(1, len(sectionType) + 1):
        if(i == type.value):
            return bytearray([i])
    return bytearray([0x00])

def byte_to_st(byte):
    if(byte > 17):
        return -1
    return sectionType(byte)

# Pretty sure it'll be faster to check for well-formed-ness on the datum level
# than to have a seperate function that loops through all sections.
# Takes a [byteArray], returns a bool
# Transaction quotes (i.e. inputs) have the form (txhash, output_index)
def input_datum_well_formed(datum):
    if(len(datum.dx) != 2 or len(datum.dx[0]) != 64 or len(datum.dx[1]) != 4):
        return False
    else:
        return True

# Basically does the same as input_datum_well_formed, but instead checks
# for a  (recipient, color, quantity) - like structure
def output_datum_well_formed(datum):
    if(len(datum.dx) != 3 or len(datum.dx[0]) != 32 or len(datum.dx[1]) != 32 or len(datum.dx[2]) != 4):
        return False
    else:
        return True

def coincolor_section_well_formed(section):
    if(len(section.data) != 1 or len(section.data[0].dx) != 1 or len(section.data[0].dx[0]) != 32):
        return False
    else:
        return True

def authed_minter_datum_well_formed(datum):
    if(len(datum.dx) != 1 or len(datum.dx[0]) != 32):
        return False
    else:
        return True

def deauthed_minter_datum_well_formed(datum):
    if(len(datum.dx) != 1 or len(datum.dx[0]) != 32):
        return False
    else:
        return True

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

    def tx_contains_section(self, sx_type):
        for sx in sections:
            # Possible error: what if sx_type is invalid?
            if(sx.type == sx_type):
                return True
        return False

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
def transaction_is_valid(txHashChain, tx):
    # Alright, so we need a 'for' loop to iterate through the sections

    # If we come across a signature, hash the catted bytes of all previous
    # Sections and assert that it matches the first data point in

    # Preliminary version: Only works with non-wildcard shuffles

    # A set of the owners of non-wildcard inputs
    owners = {}

    # A mapping of colors to quantity of coins
    inputs = {}

    # A mapping of colors to quantities. We don't care about recipients because
    # -- well, we don't care about recipients. The point of this is to make
    # sure that coins aren't created out of nowhere
    outputs = {}

    # Same as outputs, but we'll definitely have to seperate newly minted coins
    # from previously minted ones.
    mint_outputs = {}

    # A set of sections that we pass by. Note that we don't allow duplicate
    # sections -- being dumb has a direct consequence (i.e. storing txchain) to
    # the MCM maintainer.
    seen_secs = set()

    # A bytearray of catted section bytes that we've passed by so far. When we
    # encounter a signature, we hash seen_bytes and use that for the sigs.
    seen_bytes = bytearray([])

    # In case we come across a 'coincolor' section, we need to remember which
    # color is in question.
    coin_color = None

    # Of course, we need to keep track of the minters who are being authorized
    authed_minters = set()

    # And also those who are being deauthorized.
    deauthed_minters = {}

    # Takes a set of sectionTypes and a sectionType
    # Fails if (new in seen)
    # Else returns seen.add(new)
    def check_section_duplicate(seen, new):
        if(new in seen):
            # Fail
            print("Duplicate section: ", new)
            return

    for sx in tx.sections:
        if(sx.type == sectionType.INPUTS):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)
            for datum in sx.data:
                if(not input_datum_well_formed(datum)):
                    # Fail
                    print("Malformed input ", datum)
                    # How do we fail again?
                quote = txHashChain.find_owner_and_quantity_by_quote(datum)
                owner = quote[0]
                color = quote[1]
                quantity = int(quote[2])
                if color in inputs.keys:
                    inputs[color] += quantity
                else:
                    inputs[color] = quantity
                owners.add(owner)
                seen_bytes += [sx.sx_to_bytes()]

        elif(sx.type == sectionType.OUTPUTS):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)
            if(sectionType.INPUT not in seen_secs):
                # Fail
                print("Output comes before input! ")
                # How do we fail again?
            for datum in sx.data:
                if(not output_datum_well_formed(dx)):
                    # Fail
                    print("Malformed output ", dx)
                    # How do we fail again?
                recipient = datum.dx[0]
                color = datum.dx[1]
                quantity = int(datum.dx[2])
                if(color in outputs):
                    outputs[color] += quantity
                else:
                    outputs[color] = quantity
                seen_bytes += [sx.sx_to_bytes()]

        elif(sx.type == sectionType.SIGNATURES):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)
            if(sectionType.OUTPUT not in seen_secs or sectionType.INPUT not in seen_secs):
                # Fail
                print("Missing outputs or inputs ", sx)
                return False
            running_hash = SHA256(seen_bytes)
            noted_hash = sx.data[0].dx[0]

            if(running_hash != noted_hash):
                print("Hash mismatch between ", running_hash, " and ", noted_hash)

            addresses_signed = {}

            for signature in sx.data[1:]:
                pubkey = signature[0]
                sig = signature[1]
                proof = signature[2]
                addresses_signed.add(hash(pubkey))
                try:
                    vk = gen_pubkey_from_bytes(pubkey)
                    verify(pubkey, noted_hash, sig)
                except:
                    # Signature is invalid! Return False
                    print("Invalid signature: ", signature)
                    return False

            inputs_owners = set(inputs.keys)

            leftover_owners = inputs_owners.difference(addresses_signed)

            if(leftover_owners != {}):
                print("Not enough signatures to validate signature")
                return False

        elif(sx.type == sectionType.COINCOLOR):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)
            if(not coincolor_section_well_formed(sx)):
                # Fail
                print("Malformed coincolor section ", sx)
                return False
            color = sx.data[0].dx[0]
            coin_color = color
            seen_bytes += sx.sx_to_bytes()

        elif(sx.type == sectionType.AUTHED_MINTERS):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)

            # TODO: If coin_color has been authorized before, then the first
            # datum in the section should be the signature of an authorized minter

            for datum in sx.data:
                if(not authed_minter_datum_well_formed(datum)):
                    # Fail
                    print("Malformed authed_minter section ", sx)
                    return False
                authed_minters.add(bytes(datum.dx[0]))
            seen_bytes += sx.sx_to_bytes()

        elif(sx.type == sectionType.DEAUTHED_MINTERS):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)
            for datum in sx.data:
                if(not deauthed_minter_datum_well_formed(dx)):
                    # Fail
                    print("Malformed deauthed_minter section ", sx)
                    return False
                deauthed_minters.add(datum.dx[0])
            seen_bytes += [sx.sx_to_bytes()]

        elif(sx.type == sectionType.MINT_OUTPUTS):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)
            # This section has the same structure as output!
            for datum in sx.data:
                if(not output_datum_well_formed(dx)):
                    # Fail
                    print("Malformed output ", dx)
                    # How do we fail again?
                recipient = datum.dx[0]
                color = datum.dx[1]
                quantity = int(datum.dx[2])
                if(color not in outputs):
                    mint_outputs.add(color)
                seen_bytes += [sx.sx_to_bytes()]

        elif(sx.type == sectionType.SIG_MINT):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)

            # Assert well-formed-ness
            # Assert that sx.data[0].dx[0] = HASH(seen_bytes)
            # For each signature
            #   - Validate signature
            #   - Find all coins that signer is authed for
            # Take union of all sets of mintable coins
            # Assert that {coins being minted} - {mintable coins} = {}
            running_hash = SHA256(seen_bytes)
            noted_hash = sx.data[0].dx[0]

            colors_authorized_to_mint = {}

            if(running_hash != noted_hash):
                print("Hash mismatch between ", running_hash, " and ", noted_hash)

            # Signatures of mints are structured as
            # (pubkey, signature, txhash(proof of authorization))
            for signature in sx.data[1:]:
                pubkey = signature[0]
                sig = signature[1]
                proof = signature[2]
                try:
                    vk = gen_pubkey_from_bytes(pubkey)
                    verify(pubkey, noted_hash, sig)
                except:
                    # Signature is invalid! Return False
                    print("Invalid signature: ", signature)
                    return False
                # If we got here, then the signature is valid! Now we need to
                # get all of the colors that this signature is authorized for:
                proof_transaction = txHashChain.find_tx_by_hash(proof)
                if(proof_transaction == None):
                    # Oh noes! The transaction they quoted doesn't exist!
                    print("Nonexistent proof-of-authorization", proof)
                    return False

                pubkeyhash = hash(pubkey)

                authed_colors = txHashChain.get_authed_color(pubkeyhash, proof)

                colors_authorized_to_mint.union(authed_colors)

            leftover_minted = mint_outputs.difference(colors_authorized_to_mint)

            if(leftover_minted != {}):
                print("Colors being minted without an authorized signature")
                return False
    return True        



# Simple test vector
# TODO: Write actual test cases for this
"""
d = Datum([b'ffffffffffffffffffffffffffffffff', b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"])
dp = Datum([b'gggggggggggggggggggggggggggggggg'])
s = Section(sectionType.INPUTS, [d, dp])
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

print("\n\n", byte_to_st(0x01))"""
