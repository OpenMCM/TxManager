from enum import Enum

from Crypto.Hash import SHA256
from cryptohelpers import *
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

def byte_array_to_string(b):
    p = ""
    for x in b:
        p += ''.join('{:02x}'.format(x))
    return p

# Pretty sure it'll be faster to check for well-formed-ness on the datum level
# than to have a seperate function that loops through all sections.
# Takes a [byteArray], returns a bool
# Transaction quotes (i.e. inputs) have the form (txhash, secType, output_index)
def input_datum_well_formed(datum):
    if(len(datum.dx) != 3 or len(datum.dx[0]) != 32 or len(datum.dx[2]) != 4):
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

def nonce_section_well_formed(section):
    if(len(section.data) != 1 or len(section.data[0].dx) != 1 or len(section.data[0].dx[0]) != 32):
        return False
    else:
        return True

# A datum is an n-element list of 32-byte values.
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

    def datum_to_quote(self):
        if(len(self.dx) != 3 or len(self.dx[0]) != 32 or len(self.dx[2]) != 4):
            return None
        return (self.dx[0], self.dx[1], self.dx[2])


    def dx_print(self):
        p = ""
        p += "        "
        if(len(self.dx) == 0):
            return
        for x in self.dx[0]:
            p += ''.join('{:02x}'.format(x))
        p += ",\n"
        for i in self.dx[1:len(self.dx) - 1]:
            p += "            "
            for x in i:
                p += ''.join('{:02x}'.format(x))
            p += ",\n"
        if(len(self.dx) > 1):
            p += "            "
            for x in self.dx[len(self.dx) - 1]:
                p += ''.join('{:02x}'.format(x))
        print(p)

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

    def sx_print(self):
        print("    ", self.type, "[")
        for dx in self.data:
            dx.dx_print()
        print("    ]")

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
        for sx in self.sections:
            # Possible error: what if sx_type is invalid?
            if(sx.type == sx_type):
                return sx
        return None

    def tx_contains_section(self, sx_type):
        for sx in self.sections:
            # Possible error: what if sx_type is invalid?
            if(sx.type == sx_type):
                return True
        return False

    def tx_print(self):
        txhash = hash_sha_256(self.tx_to_bytes())
        print("tx:", byte_array_to_string(txhash), "[")
        for sx in self.sections:
            sx.sx_print()
        print("]")

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

    # A mapping of colors to quantity of coins
    inputs = {}

    # Sets of addresses that own coins in the inputs and wildcard_inputs sections,
    # respectively
    inputs_owners = set()
    wildcard_inputs_owners = set()

    # A mapping of colors to quantities. We don't care about recipients because
    # -- well, we don't care about recipients. The point of this is to make
    # sure that coins aren't created out of nowhere
    outputs = {}

    # Same as outputs, but we'll definitely have to seperate newly minted coins
    # from previously minted ones. We don't keep a count here because we don't
    # care how many coins an authorized minter is creating.
    mint_outputs = set()

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
    deauthed_minters = set()

    # A list of newly authed/deauthed minters. This needs to be in the function's
    # global scope because we're gonna prepend a nonce to it that the auther
    # auther must sign.
    seen_auths = bytearray([])

    # A mapping of 32-byte pseudonyms to addresses
    wildcard_ids = {}

    # An n-byte nonce
    nonce = bytearray([])

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
                    print("Malformed input ")
                    datum.dx_print()
                    return False
                if(not txHashChain.quote_is_unspent(datum.dx)):
                    print("Error: input", datum.dx, " has already been spent")
                    return False
                quote = txHashChain.find_owner_and_quantity_by_quote(datum.dx)
                owner = bytes(quote[0])
                color = bytes(quote[1])
                quantity = int.from_bytes(quote[2], byteorder='big', signed=False)
                if color in inputs.keys():
                    inputs[color] += quantity
                    inputs_owners.add(owner)
                else:
                    inputs[color] = quantity
                    inputs_owners.add(owner)

            #seen_bytes += sx.sx_to_bytes()
        # inputs and wildcard_inputs have similar behavior, except wildcard_inputs
        # stores the owners' addresses in a different set than inputs
        if(sx.type == sectionType.WILDCARD_INPUTS):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)
            for datum in sx.data:
                if(not input_datum_well_formed(datum)):
                    # Fail
                    print("Malformed input ")
                    datum.dx_print()
                    return False
                if(not txHashChain.quote_is_unspent(datum.dx)):
                    print("Error: input", datum.dx, " has already been spent")
                    return False
                quote = txHashChain.find_owner_and_quantity_by_quote(datum.dx)
                owner = bytes(quote[0])
                color = bytes(quote[1])
                quantity = int.from_bytes(quote[2], byteorder='big', signed=False)
                if color in inputs.keys():
                    inputs[color] += quantity
                    wildcard_inputs_owners.add(owner)
                else:
                    inputs[color] = quantity
                    wildcard_inputs_owners.add(owner)
            #seen_bytes += sx.sx_to_bytes()

        # OUTPUTS and WILDCARD_CHANGE sections have the same behavior
        elif(sx.type == sectionType.OUTPUTS or
             sx.type == sectionType.WILDCARD_CHANGE):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)

            # Do we actually need this? I commented so I can decide later :P
            """if(sectionType.INPUTS not in seen_secs):
                # Fail
                print("Output comes before input! ")
                return False"""


            for datum in sx.data:
                if(not output_datum_well_formed(datum)):
                    # Fail
                    print("Malformed output ", datum)
                    return False
                recipient = datum.dx[0]
                color = bytes(datum.dx[1])
                quantity = int.from_bytes(datum.dx[2], byteorder='big', signed=False)
                if(color in outputs.keys()):
                    outputs[color] += quantity
                else:
                    outputs[color] = quantity
            #seen_bytes += sx.sx_to_bytes()

        elif(sx.type == sectionType.SIGNATURES):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)
            if(sectionType.INPUTS not in seen_secs):
                # Fail
                print("Missing outputs or inputs ", sx)
                return False

            running_hash = hash_sha_256(seen_bytes)
            noted_hash = sx.data[0].dx[0]

            if(running_hash != noted_hash):
                print("Hash mismatch between ", running_hash, " and ", noted_hash)
                return False

            addresses_signed = set()

            for signature in sx.data[1:]:
                pubkey = signature.dx[0]
                sig = signature.dx[1]
                addresses_signed.add(hash_sha_256(pubkey))
                try:
                    vk = gen_pubkey_from_bytes(pubkey)
                    verify(vk, noted_hash, sig)
                except:
                    # Signature is invalid! Return False
                    print("Invalid signature: ", signature)
                    return False

            leftover_owners = inputs_owners.difference(addresses_signed)

            if(leftover_owners != set()):
                print("Not enough signatures to validate transaction")
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
            #seen_bytes += sx.sx_to_bytes()

        elif(sx.type == sectionType.AUTHED_MINTERS):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)

            auth_tx = txHashChain.color_has_been_authorized(coin_color)

            if(auth_tx != None):
                seen_auths += nonce
                for datum in sx.data[:len(sx.data) - 1]:
                    if(not authed_minter_datum_well_formed(datum)):
                        # Fail
                        print("Malformed authed_minter section ")
                        datum.dx_print()
                        return False
                    authed_minters.add(bytes(datum.dx[0]))
                    seen_auths += datum.dx[0] + b"\n"
                # The color has been authorized before! We need to verify
                # The signature in the last datum
                sig_datum = sx.data[len(sx.data) - 1]

                try:
                    pubkey = sig_datum.dx[0]
                    sig = sig_datum.dx[1]
                    proof = sig_datum.dx[2]

                    h = hash_sha_256(bytes(seen_auths))

                    vk = gen_pubkey_from_bytes(pubkey)
                    verify(vk, h, sig)
                except Exception as e:
                    # Signature is invalid! Return False
                    print("Invalid signature: ", sig_datum.dx)
                    return False
                # If we got here, then the signature is valid! Now we need to
                # get all of the colors that this signature is authorized for:
                proof_transaction = txHashChain.find_tx_by_hash(proof)
                if(proof_transaction == None):
                    # Oh noes! The transaction they quoted doesn't exist!
                    print("Nonexistent proof-of-authorization", proof)
                    return False

                pubkeyhash = hash_sha_256(pubkey)

                authed_colors = txHashChain.get_authed_color(pubkeyhash, proof)

                if(coin_color == None):
                    print("Error: coin color not found")
                    return False

                if(bytes(coin_color) not in authed_colors):
                    print("Error: unauthorized minter's signature")
                    return False

                #seen_bytes += sx.sx_to_bytes()
            else:
                # The color has not been authorized before, and we can proceed
                # as normal
                for datum in sx.data:
                    if(not authed_minter_datum_well_formed(datum)):
                        # Fail
                        print("Malformed authed_minter section ", sx)
                        return False
                    authed_minters.add(bytes(datum.dx[0]))
                #seen_bytes += sx.sx_to_bytes()

        elif(sx.type == sectionType.DEAUTHED_MINTERS):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)

            seen_auths += nonce
            for datum in sx.data[:len(sx.data) - 1]:
                if(not deauthed_minter_datum_well_formed(datum)):
                    # Fail
                    print("Malformed deauthed_minter section ", sx)
                    return False
                deauthed_minters.add(bytes(datum.dx[0]))
                seen_auths += datum.dx[0] + b"\n"

            sig_datum = sx.data[len(sx.data) - 1]

            try:
                pubkey = sig_datum.dx[0]
                sig = sig_datum.dx[1]
                proof = sig_datum.dx[2]

                h = hash_sha_256(bytes(seen_auths))

                vk = gen_pubkey_from_bytes(pubkey)
                verify(vk, h, sig)
            except Exception as e:
                # Signature is invalid! Return False
                print("Invalid signature: ", sig_datum.dx)
                return False
            # If we got here, then the signature is valid! Now we need to
            # get all of the colors that this signature is authorized for:
            proof_transaction = txHashChain.find_tx_by_hash(proof)
            if(proof_transaction == None):
                # Oh noes! The transaction they quoted doesn't exist!
                print("Nonexistent proof-of-authorization", proof)
                return False

            pubkeyhash = hash_sha_256(pubkey)

            authed_colors = txHashChain.get_authed_color(pubkeyhash, proof)

            if(coin_color == None):
                print("Error: coin color not found")
                return False

            if(bytes(coin_color) not in authed_colors):
                print("Error: unauthorized minter's signature")
                return False

            #seen_bytes += sx.sx_to_bytes()

        elif(sx.type == sectionType.MINT_OUTPUTS):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)
            # This section has the same structure as output!
            for datum in sx.data:
                if(not output_datum_well_formed(datum)):
                    # Fail
                    print("Malformed output ", datum)
                    # How do we fail again?
                recipient = datum.dx[0]
                color = bytes(datum.dx[1])
                #quantity = int(datum.dx[2])
                quantity = int.from_bytes(datum.dx[2], byteorder='big', signed=False)
                if(color not in mint_outputs):
                    mint_outputs.add(color)
                #seen_bytes += sx.sx_to_bytes()

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

            running_hash = hash_sha_256(bytes(seen_bytes))
            noted_hash = sx.data[0].dx[0]

            # Note: We don't need to reference the nonce here, since the
            # nonce section is already hashed and signed

            colors_authorized_to_mint = set()

            if(running_hash != noted_hash):
                print("Hash mismatch between ", running_hash, " and ", noted_hash)
                return False

            # Signatures of mints are structured as
            # (pubkey, signature, txhash(proof of authorization))
            for signature in sx.data[1:]:
                pubkey = signature.dx[0]
                sig = signature.dx[1]
                proof = signature.dx[2]
                try:
                    vk = gen_pubkey_from_bytes(pubkey)
                    verify(vk, noted_hash, sig)
                except Exception as e:
                    # Signature is invalid! Return False
                    print("\n\n", e, "\n\n")
                    print("Invalid signature: ", signature)
                    return False
                # If we got here, then the signature is valid! Now we need to
                # get all of the colors that this signature is authorized for:
                proof_transaction = txHashChain.find_tx_by_hash(proof)
                if(proof_transaction == None):
                    # Oh noes! The transaction they quoted doesn't exist!
                    print("Nonexistent proof-of-authorization", proof)
                    return False

                pubkeyhash = hash_sha_256(pubkey)

                authed_colors = txHashChain.get_authed_color(pubkeyhash, proof)

                colors_authorized_to_mint = colors_authorized_to_mint.union(authed_colors)

            leftover_minted = mint_outputs.difference(colors_authorized_to_mint)

            # If we're only minting colors that we're authed to mint,
            # then leftover_minted will be an empty set.
            if(leftover_minted != set()):
                print("Colors being minted without an authorized signature")
                return False

        elif(sx.type == sectionType.NONCE):
            seen_secs.add(sx.type)
            if(not nonce_section_well_formed(sx)):
                print("Error: Malformed section")
                sx.sx_print()
                return False
            n = sx.data[0].dx[0]
            if(not txHashChain.nonce_is_unused(n)):
                print("Nonce has been used previously")
                print(n)
                return False
            nonce = n
            #seen_bytes += sx.sx_to_bytes()
        elif(sx.type == sectionType.WILDCARD_OUTPUTS):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)

            # Note: wildcard_outputs has the same properties as outputs, except
            # we need to keep a set of wildcard_id's used

            for datum in sx.data:
                if(not output_datum_well_formed(datum)):
                    # Fail
                    print("Malformed output ", datum)
                    return False
                recipient = datum.dx[0]
                color = bytes(datum.dx[1])
                quantity = int.from_bytes(datum.dx[2], byteorder='big', signed=False)
                wildcard_ids[bytes(recipient)] = None
                if(color in outputs.keys()):
                    outputs[color] += quantity
                else:
                    outputs[color] = quantity
            #seen_bytes += sx.sx_to_bytes()
        elif(sx.type == sectionType.WILDCARD_ID):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)

            for datum in sx.data:
                if(not wildcard_id_datum_well_formed(datum)):
                    # Fail
                    print("Malformed wildcard id ", datum)
                    return False
                else:
                    pseudonym = datum.dx[0]
                    address = datum.dx[1]
                    wildcard_ids[bytes(pseudonym)] = address
            #seen_bytes += sx.sx_to_bytes()

        elif(sx.type == sectionType.WILDCARD_SIGNATURES):
            check_section_duplicate(seen_secs, sx.type)
            seen_secs.add(sx.type)
            if(sectionType.INPUTS not in seen_secs):
                # Fail
                print("Missing outputs or inputs ", sx)
                return False

            running_hash = hash_sha_256(seen_bytes)
            noted_hash = sx.data[0].dx[0]

            if(running_hash != noted_hash):
                print("Hash mismatch between ", running_hash, " and ", noted_hash)
                return False

            addresses_signed = set()

            for signature in sx.data[1:]:
                pubkey = signature.dx[0]
                sig = signature.dx[1]
                addresses_signed.add(hash_sha_256(pubkey))
                try:
                    vk = gen_pubkey_from_bytes(pubkey)
                    verify(vk, noted_hash, sig)
                except:
                    # Signature is invalid! Return False
                    print("Invalid signature: ", signature)
                    return False

            leftover_owners = wildcard_inputs_owners.difference(addresses_signed)

            if(leftover_owners != set()):
                print("Not enough signatures to validate transaction")
                return False

        # Regardless of which section type we saw, we need to add it to the
        # Seen_bytes
        seen_bytes += sx.sx_to_bytes()

    # Assert non-negative entropy
    for color in outputs.keys():
        try:
            if(inputs[color] < outputs[color]):
                # Fail
                print("Error: non-negative entropy in coin color ", color)
                return False
        except Exception as e:
            print("\n\ne\n\n")
            return False

    # Check that we have seen all the required sections
    transfer_tx = set([sectionType.INPUTS, sectionType.OUTPUTS, sectionType.SIGNATURES])
    tx_burn = set([sectionType.INPUTS, sectionType.SIGNATURES])
    mint_tx = set([sectionType.NONCE, sectionType.MINT_OUTPUTS, sectionType.SIG_MINT])
    auth_tx = set([sectionType.NONCE, sectionType.AUTHED_MINTERS, sectionType.COINCOLOR])
    deauth_tx = set([sectionType.NONCE, sectionType.DEAUTHED_MINTERS, sectionType.COINCOLOR])
    auth_deauth_tx = set([sectionType.NONCE, sectionType.AUTHED_MINTERS, sectionType.DEAUTHED_MINTERS, sectionType.COINCOLOR])

    # This bit is kinda dumb. Apparently sets aren't hashable in python, so we
    # need to check whether the transaction is well-formed for each possible
    # structure with a really big 'if' statement.
    if(seen_secs == transfer_tx or seen_secs == mint_tx or seen_secs == auth_tx or seen_secs == deauth_tx or seen_secs == auth_deauth_tx or seen_secs == tx_burn):
        return True
    else:
        print("Malformed transaction: ")
        print(seen_secs)
        return False
    # TODO: Write a hash function for sets
    # NOTE: Here's a way to do this:
    # We have a list of unique prime numbers, p, that has the same length as
    # the list of all possible sections.
    # We represent a transaction's section structure as a list of 0's and 1's,
    # where a 1 represents a sectionType's presence in a transaction, and a 0
    # the sectionType's absence. Let's call this list s
    # We let hash = product(p[i] ** s[i] for i in len(p))
    # Two transactions with the same sections in different orders will have the
    # same hash by commutativity of multiplication. Two transactions with
    # different sections will not have the same hash, by the Fundamental
    # Theorem of Arithmetic.
