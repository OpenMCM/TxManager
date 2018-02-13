import transaction
from transaction import Datum
from transaction import Section
from transaction import Transaction
from transaction import sectionType
from transaction import bytes_to_tx
from transaction import *

from cryptohelpers import *

bottom_hash = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

class TXHashChain:
    def __init__(self):
        # Gotta make a genesis block with arbitrary prevHash and transaction
        bottom_tx = Transaction([])

        bottom_block_hash = hash_sha_256(bottom_hash + bottom_tx.tx_to_bytes())

        self.most_recent_block = bottom_block_hash
        self.chain = {bottom_block_hash:(bottom_hash, bottom_tx)}

    # Takes a transaction, tries to insert it. Returns a bool denoting success.
    # Phew. That was hard
    def insert_tx(self, tx):
        # Assume tx is a Transaction object

        # This is called "Pokemon error handling", and it's a really bad coding
        # practice because we basically catch any and all errors indiscriminately,
        # meaning that we don't actually understand what our code is doing.
        # Thing is, in this case it's actually acceptable to do because a transaction
        # that causes an error is inherently invalid, and we should reject it
        # anyways.
        try:
            # Assert that the transaction is valid before inserting
            if not transaction_is_valid(self, tx):
                print("Error: invalid transaction")
                return False
        except Exception as e:
            print("Error: invalid transaction caused error", e)
            return False

        # Create a new block by catting top_hash || txbytes
        new_block = (self.most_recent_block, tx)

        # Calc new block hash
        new_block_hash = hash_sha_256(new_block[0] + new_block[1].tx_to_bytes())

        # Insert the new block into the chain
        self.chain[new_block_hash] = new_block
        self.most_recent_block = new_block_hash
        return True

    def find_tx_by_hash(self, txhash):
        # Iterate through TXHashChain to find a transaction with the given txhash

        curr_hash = self.most_recent_block

        while curr_hash != bottom_hash:
            curr_block = self.chain[curr_hash]
            curr_tx = curr_block[1]
            curr_tx_hash = hash_sha_256(curr_tx.tx_to_bytes())
            if(curr_tx_hash == txhash):
                return curr_tx
            else:
                curr_hash = curr_block[0]

        return None

    # Returns a txhash where the color is authorized to be minted if one exists,
    # and None otherwise.
    def color_has_been_authorized(self, color):
        curr_hash = self.most_recent_block

        while curr_hash != bottom_hash:
            curr_block = self.chain[curr_hash]
            curr_tx = curr_block[1]
            curr_tx_hash = hash_sha_256(curr_tx.tx_to_bytes())

            coin_color_section = curr_tx.get_section(sectionType.COINCOLOR)
            if(coin_color_section != None):
                if(coin_color_section.data[0].dx[0] == color):
                    return curr_tx_hash

            curr_hash = curr_block[0]
        return None

    # Verifies that pubkeyhash is an authorized minter of the color specified
    # at txhash. Also verifies that pubkeyhash has not been deauthorized since
    # txhash was issued. Returns a set of colors.
    def get_authed_color(self, pubkeyhash, txhash):
        curr_hash = self.most_recent_block

        authorized_colors = set()
        deauthorized_colors = set()

        while curr_hash != bottom_hash:
            curr_block = self.chain[curr_hash]
            curr_tx = curr_block[1]
            curr_tx_hash = hash_sha_256(curr_tx.tx_to_bytes())
            if(curr_tx_hash == txhash):
                color_section = curr_tx.get_section(sectionType.COINCOLOR)
                color = color_section.data[0].dx[0]
                auth_section = curr_tx.get_section(sectionType.AUTHED_MINTERS)
                if(auth_section == None):
                    print("Error: transaction", txhash, "Does not authorize any minters")
                    return None
                for minter in auth_section.data:
                    if minter.dx[0] == pubkeyhash:
                        authorized_colors.add(bytes(color))
            else:
                deauth_section = curr_tx.get_section(sectionType.DEAUTHED_MINTERS)
                if(deauth_section != None):
                    color_section = curr_tx.get_section(sectionType.COINCOLOR)
                    color = color_section.data[0].dx[0]
                    for minter in deauth_section.data:
                        if minter.dx[0] == pubkeyhash:
                            deauthorized_colors.add(bytes(color))

            curr_hash = curr_block[0]

        return authorized_colors.difference(deauthorized_colors)

    def txHashChain_print(self):
        curr_hash = self.most_recent_block

        while curr_hash != bottom_hash:
            curr_block = self.chain[curr_hash]
            curr_tx = curr_block[1]

            print("Block Hash: ", byte_array_to_string(curr_hash))
            curr_tx.tx_print()
            print("\n")

            curr_hash = curr_block[0]

    # Takes a (txhash, section_id, output_index) as argument
    # Returns a bool denoting whether the given quote has been referenced
    # in an input before
    def quote_is_unspent(self, quote):
        curr_hash = self.most_recent_block

        while curr_hash != bottom_hash:
            curr_block = self.chain[curr_hash]
            curr_tx = curr_block[1]

            inputs_section = curr_tx.get_section(sectionType.INPUTS)
            if(inputs_section != None):
                for q in inputs_section.data:
                    if(q.dx == quote):
                        return False

            inputs_section = curr_tx.get_section(sectionType.PAINT_INPUTS)
            if(inputs_section != None):
                for q in inputs_section.data:
                    if(q.dx == quote):
                        return False

            if(hash_sha_256(curr_tx.tx_to_bytes()) == quote[0]):
                return True

            curr_hash = curr_block[0]

    # Takes a (txhash, section_id, output_index) as argument
    # Returns (owner, color, quantity) or (owner, quantity)
    #   - Note: Will only return (owner, quantity) if we allow for black coins!
    def find_owner_and_quantity_by_quote(self, quote):
        txhash = quote[0]
        output_index = int.from_bytes(quote[2], byteorder='big', signed=False)

        tx = self.find_tx_by_hash(txhash)

        sec_type = sectionType(int.from_bytes(quote[1], byteorder='big', signed=False))
        if(sec_type != sectionType.MINT_OUTPUTS and sec_type != sectionType.OUTPUTS and sec_type != sectionType.PAINT_OUTPUTS):
            return None
        # Get transaction output section
        outputs = tx.get_section(sec_type)

        # The output is alread organized as a list of (o, c, q), so we can
        # just return the index in the output from here.
        return outputs.data[output_index].dx

    # Iterate through txHashChain and verify that a given nonce has never
    # been used before
    def nonce_unused(self, nonce):
        print("Placeholder")
