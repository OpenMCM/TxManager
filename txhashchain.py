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

        bottom_block_hash = hash(bottom_hash + bottom_tx.tx_to_bytes())

        self.most_recent_block = bottom_block_hash
        self.chain = {bottom_block_hash:(bottom_hash, bottom_tx)}

    def insert_tx(self, tx):
        # Assume tx is a Transaction object

        # Create a new block by catting top_hash || txbytes
        new_block = (self.most_recent_block, tx)

        # Calc new block hash
        new_block_hash = hash(new_block[0] + new_block[1].tx_to_bytes())

        # Insert the new block into the chain
        self.chain[new_block_hash] = new_block
        self.most_recent_block = new_block_hash

    def find_tx_by_hash(self, txhash):
        # Iterate through TXHashChain to find a transaction with the given txhash

        curr_hash = self.most_recent_block

        while curr_hash != bottom_hash:
            curr_block = self.chain[curr_hash]
            curr_tx = curr_block[1]
            curr_tx_hash = hash(curr_tx.tx_to_bytes())
            if(curr_tx_hash == txhash):
                return curr_tx
            else:
                curr_hash = curr_block[0]


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

thc = TXHashChain()

thc.insert_tx(t)
thc.insert_tx(t2)
print(thc.find_tx_by_hash(hash(t2.tx_to_bytes())).tx_to_bytes())
