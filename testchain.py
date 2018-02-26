from txhashchain import *
from transaction import *
from cryptohelpers import *
import random
import os

# Fuzzing helper functions
def random_tx():
    sx_list = []
    for i in range(0, random.randint(0, 10)):
        sx_list += [random_sx()]
    return Transaction(sx_list)

def random_sx():
    dx_list = []
    for i in range(0, random.randint(0, 100)):
        dx_list += [random_dx()]
    sx_section = sectionType(random.randint(1, 19))
    return Section(sx_section, dx_list)

def random_dx():
    l = []
    for i in range(0, random.randint(0, 100)):
        # Make a 32-byte value
        if(i % 5 == 1):
            l += bytearray([32])
        elif(i % 5 == 2):
            l += bytearray([64])
        elif(i % 5 == 3):
            l += bytearray([4])
        else:
            l += bytearray([random.randint(0, 100)])
    return Datum(l)

txHC = TXHashChain()

alice_sk = gen_privkey()
alice_vk = gen_pubkey(alice_sk)
alice_ad = hash_sha_256(alice_vk.to_string())
alice_adp = hash_sha_256(bytearray(alice_vk.to_string()))

bob_sk = gen_privkey()
bob_vk = gen_pubkey(bob_sk)
bob_ad = hash_sha_256(bob_vk.to_string())
bob_adp = hash_sha_256(bytearray(bob_vk.to_string()))

charlie_sk = gen_privkey()
charlie_vk = gen_pubkey(charlie_sk)
charlie_ad = hash_sha_256(charlie_vk.to_string())
charlie_adp = hash_sha_256(bytearray(charlie_vk.to_string()))

mallory_sk = gen_privkey()
mallory_vk = gen_pubkey(mallory_sk)
mallory_ad = hash_sha_256(mallory_vk.to_string())
mallory_adp = hash_sha_256(bytearray(mallory_vk.to_string()))

alice_coin_color = bytearray(b"\xde\xad\xbe\xef" * 8)
alice_coin_prime_color = bytearray(b"\x00\xc0\xff\xee" * 8)

print("Alice's pubkey: ", alice_vk.to_string())
print("Alice's addr: ", alice_ad)

print("Bob's pubkey: ", bob_vk.to_string())
print("Bob's address: ", bob_ad)

print("Charlie's pubkey: ", charlie_vk.to_string())
print("Charlie's address: ", charlie_ad)

print("Mallory's pubkey: ", mallory_vk.to_string())
print("Mallory's address: ", mallory_ad)

print("Beginning standard test suite...")

# Alice authorizes herself to mint AliceCoin
# This transaction takes the form:
#   coincolor: [
#       deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
#   ]
#   authed_minters: [
#       <alice_ad>
#   ]
#   Note that authed_minters doesn't have a signature! The txHC should ignore
#   this because the color deadbeef x 8 has never been authorized before.
print()
print("Constructing color section...")
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

print("Constructing nonce section...")
nonce_datum = Datum([txHC.generate_unused_nonce()])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

print("Constructing authed_minters section...")
authed_datum = Datum([bytearray(alice_ad)])
authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum])

print("Constructing transaction...")
tx_auth_alice = Transaction([nonce_section, color_section, authed_section])
tx_auth_alice_hash = hash_sha_256(tx_auth_alice.tx_to_bytes())
first_tx_hash = tx_auth_alice_hash
print("Final transaction bytes: \n", tx_auth_alice.tx_to_bytes(), "\n\n")

if(txHC.insert_tx(tx_auth_alice)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Alice mints 2 AC, sends to herself
nonce_datum = Datum([txHC.generate_unused_nonce()])
nonce_section = Section(sectionType.NONCE, [nonce_datum])
mint_outputs_datum = Datum([bytearray(alice_ad), alice_coin_color, bytearray(b"\x00\x02\x00\x00")])
mint_outputs_section = Section(sectionType.MINT_OUTPUTS, [mint_outputs_datum])

sig_bytes = bytes(mint_outputs_section.sx_to_bytes()) + bytes(nonce_section.sx_to_bytes())

sig_mnt_hash_sha_256 = Datum([hash_sha_256(sig_bytes)])


sig = sign(alice_sk, hash_sha_256(sig_bytes))

sig_mnt_datum = Datum([alice_vk.to_string(), sig, hash_sha_256(tx_auth_alice.tx_to_bytes())])

sig_mnt_section = Section(sectionType.SIG_MINT, [sig_mnt_hash_sha_256, sig_mnt_datum])

tx_mnt_two = Transaction([mint_outputs_section, nonce_section, sig_mnt_section])
tx_mnt_two_hash = hash_sha_256(tx_mnt_two.tx_to_bytes())

if(txHC.insert_tx(tx_mnt_two)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Alice sends 1 AC to Bob, 1 AC to herself
inputs_datum = Datum([tx_mnt_two_hash, bytes([sectionType.MINT_OUTPUTS.value]), b'\x00\x00\x00\x00'])
inputs_section = Section(sectionType.INPUTS, [inputs_datum])

outputs_datum_alice = Datum([alice_ad, alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
outputs_datum_bob = Datum([bob_ad, alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
outputs_section = Section(sectionType.OUTPUTS, [outputs_datum_alice, outputs_datum_bob])

section_bytes = inputs_section.sx_to_bytes() + outputs_section.sx_to_bytes()

tx_transfer_hash = hash_sha_256(bytes(section_bytes))

sig_transfer = sign(alice_sk, tx_transfer_hash)
sig_transfer_datum = Datum([alice_vk.to_string(), bytes(sig_transfer)])
sig_hash_datum = Datum([tx_transfer_hash])
sig_transfer_section = Section(sectionType.SIGNATURES, [sig_hash_datum, sig_transfer_datum])

tx_transfer = Transaction([inputs_section, outputs_section, sig_transfer_section])
tx_transfer_hash = hash_sha_256(bytes(tx_transfer.tx_to_bytes()))

if(txHC.insert_tx(tx_transfer)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Bob sends his AC to Alice
inputs_transfer_two = Datum([tx_transfer_hash, bytes([sectionType.OUTPUTS.value]), bytearray(b"\x00\x00\x00\x01")])
inputs_section_two = Section(sectionType.INPUTS, [inputs_transfer_two])

outputs_transfer_two = Datum([alice_ad, alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
outputs_section_two = Section(sectionType.OUTPUTS, [outputs_transfer_two])

section_bytes_two = inputs_section_two.sx_to_bytes() + outputs_section_two.sx_to_bytes()
tx_transfer_two_hash = hash_sha_256(section_bytes_two)

sig_transfer_two = sign(bob_sk, tx_transfer_two_hash)
sig_transfer_two_datum = Datum([bob_vk.to_string(), bytes(sig_transfer_two)])
sig_hash_two_datum = Datum([tx_transfer_two_hash])
sig_transfer_two_section = Section(sectionType.SIGNATURES, [sig_hash_two_datum, sig_transfer_two_datum])

tx_transfer_two = Transaction([inputs_section_two, outputs_section_two, sig_transfer_two_section])
tx_transfer_two_hash = hash_sha_256(bytes(tx_transfer_two.tx_to_bytes()))

if(txHC.insert_tx(tx_transfer_two)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Bob, quoting the original transaction, tries to send his old AC back to himself
inputs_transfer_two = Datum([tx_transfer_hash, bytes([sectionType.OUTPUTS.value]), bytearray(b"\x00\x00\x00\x01")])
inputs_section_two = Section(sectionType.INPUTS, [inputs_transfer_two])

outputs_transfer_two = Datum([bob_ad, alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
outputs_section_two = Section(sectionType.OUTPUTS, [outputs_transfer_two])

section_bytes_two = inputs_section_two.sx_to_bytes() + outputs_section_two.sx_to_bytes()
tx_transfer_two_hash = hash_sha_256(section_bytes_two)

sig_transfer_two = sign(bob_sk, tx_transfer_two_hash)
sig_transfer_two_datum = Datum([bob_vk.to_string(), bytes(sig_transfer_two)])
sig_hash_two_datum = Datum([tx_transfer_two_hash])
sig_transfer_two_section = Section(sectionType.SIGNATURES, [sig_hash_two_datum, sig_transfer_two_datum])

tx_transfer_two = Transaction([inputs_section_two, outputs_section_two, sig_transfer_two_section])
tx_transfer_two_hash = hash_sha_256(bytes(tx_transfer_two.tx_to_bytes()))

if(txHC.insert_tx(tx_transfer_two)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")


# Bob, quoting the original transaction, tries to send one of Alice's coins to himself
inputs_transfer_three = Datum([tx_transfer_hash, bytes([sectionType.OUTPUTS.value]), bytearray(b"\x00\x00\x00\x00")])
inputs_section_three = Section(sectionType.INPUTS, [inputs_transfer_three])

outputs_transfer_three = Datum([bob_ad, alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
outputs_section_three = Section(sectionType.OUTPUTS, [outputs_transfer_three])

section_bytes_three = inputs_section_three.sx_to_bytes() + outputs_section_three.sx_to_bytes()
tx_transfer_three_hash = hash_sha_256(section_bytes_three)

sig_transfer_three = sign(bob_sk, tx_transfer_three_hash)
sig_transfer_three_datum = Datum([bob_vk.to_string(), bytes(sig_transfer_three)])
sig_hash_three_datum = Datum([tx_transfer_three_hash])
sig_transfer_three_section = Section(sectionType.SIGNATURES, [sig_hash_three_datum, sig_transfer_three_datum])

tx_transfer_three = Transaction([inputs_section_three, outputs_section_three, sig_transfer_three_section])
tx_transfer_three_hash = hash_sha_256(bytes(tx_transfer_three.tx_to_bytes()))

if(txHC.insert_tx(tx_transfer_three)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")


# Bob authorizes himself to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

authed_datum = Datum([bytearray(bob_ad)])
authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum])

tx_auth_bob = Transaction([color_section, authed_section])

if(txHC.insert_tx(tx_auth_bob)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")

# Bob reissues Alice's minting transaction
if(txHC.insert_tx(tx_mnt_two)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")

# Bob reissues Alice's transfer transaction
if(txHC.insert_tx(tx_transfer)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")


# Alice authorizes Bob to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

nonce = txHC.generate_unused_nonce()
nonce_datum = Datum([nonce])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

authed_datum = Datum([bytearray(bob_ad)])

bob_addr_hash = hash_sha_256(nonce + bytes(bob_ad + b"\n"))
alice_auth_bob_sig = sign(alice_sk, bob_addr_hash)
alice_auth_bob_sig_datum = Datum([alice_vk.to_string(), alice_auth_bob_sig, tx_auth_alice_hash])

authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum, alice_auth_bob_sig_datum])

tx_auth_bob_forreal = Transaction([nonce_section, color_section, authed_section])
tx_auth_bob_forreal_hash = hash_sha_256(tx_auth_bob_forreal.tx_to_bytes())

if(txHC.insert_tx(tx_auth_bob_forreal)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Bob mints 1 AC, sends to self
mint_outputs_datum = Datum([bytearray(bob_ad), alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
mint_outputs_section = Section(sectionType.MINT_OUTPUTS, [mint_outputs_datum])

nonce_datum = Datum([txHC.generate_unused_nonce()])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

sig_bytes = bytes(nonce_section.sx_to_bytes() + mint_outputs_section.sx_to_bytes())
sig_mnt_hash_sha_256 = Datum([hash_sha_256(sig_bytes)])

sig = sign(bob_sk, hash_sha_256(sig_bytes))

sig_mnt_datum = Datum([bob_vk.to_string(), bytes(sig), hash_sha_256(tx_auth_bob_forreal.tx_to_bytes())])

sig_mnt_section = Section(sectionType.SIG_MINT, [sig_mnt_hash_sha_256, sig_mnt_datum])

tx_mnt_two = Transaction([nonce_section, mint_outputs_section, sig_mnt_section])
tx_mnt_two_hash = hash_sha_256(tx_mnt_two.tx_to_bytes())
tx_bob_gets_back_hash = tx_mnt_two_hash

if(txHC.insert_tx(tx_mnt_two)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Bob deauthorizes himself to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

nonce = txHC.generate_unused_nonce()
nonce_datum = Datum([nonce])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

deauthed_datum = Datum([bytearray(bob_ad)])

bob_addr_hash = hash_sha_256(nonce + bytes(bob_ad + b"\n"))
bob_deauth_bob_sig = sign(bob_sk, bob_addr_hash)
bob_deauth_bob_sig_datum = Datum([bob_vk.to_string(), bob_deauth_bob_sig, tx_auth_bob_forreal_hash])

deauthed_section = Section(sectionType.DEAUTHED_MINTERS, [deauthed_datum, bob_deauth_bob_sig_datum])

tx_bob_deauth_bob = Transaction([nonce_section, color_section, deauthed_section])

if(txHC.insert_tx(tx_bob_deauth_bob)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Bob mints 2 AC, sends to self
mint_outputs_datum = Datum([bytearray(bob_ad), alice_coin_color, bytearray(b"\x00\x02\x00\x00")])
mint_outputs_section = Section(sectionType.MINT_OUTPUTS, [mint_outputs_datum])

sig_mnt_hash_sha_256 = Datum([hash_sha_256(bytes(mint_outputs_section.sx_to_bytes()))])


sig = sign(alice_sk, hash_sha_256(bytes(mint_outputs_section.sx_to_bytes())))

sig_mnt_datum = Datum([bob_vk.to_string(), bytes(sign(bob_sk, hash_sha_256(mint_outputs_section.sx_to_bytes()))), hash_sha_256(tx_auth_bob_forreal.tx_to_bytes())])

sig_mnt_section = Section(sectionType.SIG_MINT, [sig_mnt_hash_sha_256, sig_mnt_datum])

tx_mnt_two = Transaction([mint_outputs_section, sig_mnt_section])
tx_mnt_two_hash = hash_sha_256(tx_mnt_two.tx_to_bytes())

if(txHC.insert_tx(tx_mnt_two)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")


# Alice authorizes Charlie to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

nonce = txHC.generate_unused_nonce()
nonce_datum = Datum([nonce])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

authed_datum = Datum([bytearray(charlie_ad)])

charlie_addr_hash = hash_sha_256(bytes(nonce + charlie_ad + b"\n"))
alice_auth_charlie_sig = sign(alice_sk, charlie_addr_hash)
alice_auth_charlie_sig_datum = Datum([alice_vk.to_string(), alice_auth_charlie_sig, tx_auth_alice_hash])

authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum, alice_auth_charlie_sig_datum])

tx_auth_charlie_forreal = Transaction([nonce_section, color_section, authed_section])
tx_auth_charlie_forreal_hash = hash_sha_256(tx_auth_charlie_forreal.tx_to_bytes())

if(txHC.insert_tx(tx_auth_charlie_forreal)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Charlie deauthorizes Alice to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

nonce = txHC.generate_unused_nonce()
nonce_datum = Datum([nonce])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

deauthed_datum = Datum([bytearray(alice_ad)])

alice_addr_hash = hash_sha_256(bytes(nonce + alice_ad + b"\n"))
charlie_deauth_alice_sig = sign(charlie_sk, alice_addr_hash)
charlie_deauth_alice_sig_datum = Datum([charlie_vk.to_string(), charlie_deauth_alice_sig, tx_auth_charlie_forreal_hash])

deauthed_section = Section(sectionType.DEAUTHED_MINTERS, [deauthed_datum, charlie_deauth_alice_sig_datum])

tx_charlie_deauth_alice = Transaction([nonce_section, color_section, deauthed_section])

if(txHC.insert_tx(tx_charlie_deauth_alice)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Charlie authorizes Mallory to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

nonce = txHC.generate_unused_nonce()
nonce_datum = Datum([nonce])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

deauthed_datum = Datum([bytearray(mallory_ad)])

mallory_addr_hash = hash_sha_256(bytes(nonce + mallory_ad + b"\n"))
charlie_auth_mallory_sig = sign(charlie_sk, mallory_addr_hash)
charlie_auth_mallory_sig_datum = Datum([charlie_vk.to_string(), charlie_auth_mallory_sig, tx_auth_charlie_forreal_hash])

authed_section = Section(sectionType.AUTHED_MINTERS, [deauthed_datum, charlie_auth_mallory_sig_datum])

tx_charlie_auth_mallory = Transaction([nonce_section, color_section, authed_section])
tx_charlie_auth_mallory_hash = hash_sha_256(bytes(tx_charlie_auth_mallory.tx_to_bytes()))

if(txHC.insert_tx(tx_charlie_auth_mallory)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Alice authorizes herself to mint AliceCoinPrime
color_datum = Datum([alice_coin_prime_color])
color_section = Section(sectionType.COINCOLOR, [color_datum])

nonce = txHC.generate_unused_nonce()
nonce_datum = Datum([nonce])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

authed_datum = Datum([bytearray(alice_ad)])
authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum])
tx_auth_alice = Transaction([nonce_section, color_section, authed_section])
tx_auth_alice_hash = hash_sha_256(tx_auth_alice.tx_to_bytes())
tx_permanent = tx_auth_alice_hash

if(txHC.insert_tx(tx_auth_alice)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Mallory tries to steal Bob's AliceCoin
inputs_datum = Datum([tx_bob_gets_back_hash, bytes([sectionType.MINT_OUTPUTS.value]), bytearray(b"\x00\x00\x00\x00")])
inputs_section = Section(sectionType.INPUTS, [inputs_datum])

outputs_datum = Datum([mallory_ad, alice_coin_color, b"\x00\x01\x00\x00"])
outputs_section = Section(sectionType.OUTPUTS, [outputs_datum])

in_out_bytes = inputs_section.sx_to_bytes() + outputs_section.sx_to_bytes()
sx_hash = hash_sha_256(bytes(in_out_bytes))

sec_hash_datum = Datum([sx_hash])
sig_datum = Datum([mallory_vk.to_string(), sign(mallory_sk, sx_hash)])
sig_section = Section(sectionType.SIGNATURES, [sec_hash_datum, sig_datum])

tx = Transaction([inputs_section, outputs_section, sig_section])

if(txHC.insert_tx(tx)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")

# Mallory tries to steal Bob's AliceCoin again, this time with no signature at all
inputs_datum = Datum([tx_bob_gets_back_hash, bytes([sectionType.MINT_OUTPUTS.value]), bytearray(b"\x00\x00\x00\x00")])
inputs_section = Section(sectionType.INPUTS, [inputs_datum])

outputs_datum = Datum([mallory_ad, alice_coin_color, b"\x00\x01\x00\x00"])
outputs_section = Section(sectionType.OUTPUTS, [outputs_datum])

in_out_bytes = inputs_section.sx_to_bytes() + outputs_section.sx_to_bytes()
sx_hash = hash_sha_256(bytes(in_out_bytes))

tx = Transaction([inputs_section, outputs_section])

if(txHC.insert_tx(tx)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")

# Mallory tries to mint AliceCoin out of thin air, quoting no inputs
inputs_datum = Datum([])
inputs_section = Section(sectionType.INPUTS, [inputs_datum])

outputs_datum = Datum([mallory_ad, alice_coin_color, b"\x00\x01\x00\x00"])
outputs_section = Section(sectionType.OUTPUTS, [outputs_datum])

in_out_bytes = inputs_section.sx_to_bytes() + outputs_section.sx_to_bytes()
sx_hash = hash_sha_256(bytes(in_out_bytes))

sec_hash_datum = Datum([sx_hash])
sig_datum = Datum([mallory_vk.to_string(), sign(mallory_sk, sx_hash)])
sig_section = Section(sectionType.SIGNATURES, [sec_hash_datum, sig_datum])

tx = Transaction([inputs_section, outputs_section, sig_section])

if(txHC.insert_tx(tx)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")

# Mallory authorizes himself to mint AliceCoinPrime with his own signature
color_datum = Datum([alice_coin_prime_color])
color_section = Section(sectionType.COINCOLOR, [color_datum])
sig_datum = Datum([mallory_vk.to_string(), sign(mallory_sk, hash_sha_256(bytes(mallory_ad + b"\n"))), first_tx_hash])
authed_datum = Datum([bytearray(mallory_ad)])
authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum, sig_datum])
tx_auth_mallory = Transaction([color_section, authed_section])
tx_auth_mallory_hash = hash_sha_256(tx_auth_mallory.tx_to_bytes())

if(txHC.insert_tx(tx_auth_mallory)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")

# Mallory authorizes himself to mint AliceCoinPrime with no signature
color_datum = Datum([alice_coin_prime_color])
color_section = Section(sectionType.COINCOLOR, [color_datum])
authed_datum = Datum([bytearray(mallory_ad)])
authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum])
tx_auth_mallory = Transaction([color_section, authed_section])
tx_auth_mallory_hash = hash_sha_256(tx_auth_mallory.tx_to_bytes())


if(txHC.insert_tx(tx_auth_mallory)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")

# Mallory deauthorizes Charlie to mint AliceCoin
# Charlie authorizes Mallory to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

nonce = txHC.generate_unused_nonce()
nonce_datum = Datum([nonce])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

deauthed_datum = Datum([bytearray(charlie_ad)])

charlie_addr_hash = hash_sha_256(bytes(nonce + charlie_ad + b"\n"))

mallory_deauth_charlie_sig = sign(mallory_sk, charlie_addr_hash)
mallory_deauth_charlie_sig_datum = Datum([mallory_vk.to_string(), mallory_deauth_charlie_sig, tx_charlie_auth_mallory_hash])

deauthed_section = Section(sectionType.DEAUTHED_MINTERS, [deauthed_datum, mallory_deauth_charlie_sig_datum])

tx_mallory_deauth_charlie = Transaction([nonce_section, color_section, deauthed_section])

if(txHC.insert_tx(tx_mallory_deauth_charlie)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Charlie authorizes Alice to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

authed_datum = Datum([bytearray(alice_ad)])

alice_addr_hash = hash_sha_256(bytes(alice_ad + b"\n"))
charlie_auth_alice_sig = sign(charlie_sk, alice_addr_hash)
charlie_auth_alice_sig_datum = Datum([charlie_vk.to_string(), charlie_auth_alice_sig, tx_auth_charlie_forreal_hash])

authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum, charlie_auth_alice_sig_datum])

tx_charlie_auth_alice = Transaction([color_section, authed_section])
tx_charlie_auth_alice_hash = hash_sha_256(bytes(tx_charlie_auth_alice.tx_to_bytes()))

if(txHC.insert_tx(tx_charlie_auth_alice)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")

# Mallory mints 1 AC, sends to himself
mint_outputs_datum = Datum([bytearray(mallory_ad), alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
mint_outputs_section = Section(sectionType.MINT_OUTPUTS, [mint_outputs_datum])

nonce = txHC.generate_unused_nonce()
nonce_datum = Datum([nonce])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

sig_bytes = bytes(nonce_section.sx_to_bytes() + mint_outputs_section.sx_to_bytes())

sig_mnt_hash_sha_256 = Datum([hash_sha_256(sig_bytes)])


sig = sign(mallory_sk, hash_sha_256(sig_bytes))

sig_mnt_datum = Datum([mallory_vk.to_string(), bytes(sign(mallory_sk, hash_sha_256(sig_bytes))), tx_charlie_auth_mallory_hash])

sig_mnt_section = Section(sectionType.SIG_MINT, [sig_mnt_hash_sha_256, sig_mnt_datum])

tx_mnt_two = Transaction([nonce_section, mint_outputs_section, sig_mnt_section])
tx_mnt_mallory_hash = hash_sha_256(tx_mnt_two.tx_to_bytes())

if(txHC.insert_tx(tx_mnt_two)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")


# Mallory spends his AliceCoin, sends himself more than he spends
inputs_datum = Datum([tx_mnt_mallory_hash, bytes([sectionType.MINT_OUTPUTS.value]), bytearray(b"\x00\x00\x00\x00")])
inputs_section = Section(sectionType.INPUTS, [inputs_datum])

outputs_datum = Datum([mallory_ad, alice_coin_color, bytearray(b"\x00\x0f\x00\x00")])
outputs_section = Section(sectionType.OUTPUTS, [outputs_datum])

tx_bytes = inputs_section.sx_to_bytes() + outputs_section.sx_to_bytes()

mallory_sig = sign(mallory_sk, hash_sha_256(tx_bytes))
hash_datum = Datum([hash_sha_256(tx_bytes)])
sig_datum = Datum([mallory_vk.to_string(), mallory_sig])

sig_section = Section(sectionType.SIGNATURES, [hash_datum, sig_datum])

tx_mallory_overspends = Transaction([inputs_section, outputs_section, sig_section])
tx_mallory_overspends_hash = hash_sha_256(tx_mallory_overspends.tx_to_bytes())

if(txHC.insert_tx(tx_mallory_overspends)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")

# Mallory mints 1 AC, sends to himself, omits signature
mint_outputs_datum = Datum([bytearray(mallory_ad), alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
mint_outputs_section = Section(sectionType.MINT_OUTPUTS, [mint_outputs_datum])

tx_mnt_two = Transaction([mint_outputs_section])
tx_mnt_mallory_hash = hash_sha_256(tx_mnt_two.tx_to_bytes())

if(txHC.insert_tx(tx_mnt_two)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")

# Alice mints 10 ACP, sends to Mallory
mint_outs_datum = Datum([bytearray(mallory_ad), alice_coin_prime_color, bytearray(b"\x00\x0a\x00\x00")])
mint_outs_section = Section(sectionType.MINT_OUTPUTS, [mint_outs_datum])
mint_outs_section_bytes = mint_outs_section.sx_to_bytes()

nonce = txHC.generate_unused_nonce()
nonce_datum = Datum([nonce])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

mint_outs_section_hash = hash_sha_256(mint_outs_section_bytes + nonce_section.sx_to_bytes())

sig = sign(alice_sk, mint_outs_section_hash)

sig_mint_hash_datum = Datum([mint_outs_section_hash])
sig_mint_sig_datum = Datum([alice_vk.to_string(), sig, tx_permanent])
sig_mint_sig_section = Section(sectionType.SIG_MINT, [sig_mint_hash_datum, sig_mint_sig_datum])

tx_mnt_ten = Transaction([mint_outs_section, nonce_section, sig_mint_sig_section])
tx_mnt_ten_hash = hash_sha_256(tx_mnt_ten.tx_to_bytes())

if(txHC.insert_tx(tx_mnt_ten)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Mallory submits a transaction with no inputs
outputs_datum = Datum([mallory_ad, alice_coin_prime_color, bytearray(b"\x00\x0a\x00\x00")])
outputs_section = Section(sectionType.OUTPUTS, [outputs_datum])
outputs_section_hash = hash_sha_256(outputs_section.sx_to_bytes())

sig = sign(mallory_sk, outputs_section_hash)

hash_datum = Datum([outputs_section_hash])
sig_datum = Datum([mallory_vk.to_string(), sig])
sig_section = Section(sectionType.SIGNATURES, [hash_datum, sig_datum])

tx = Transaction([outputs_section, sig_section])

if(txHC.insert_tx(tx)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")


# Mallory submits a transaction with no outputs
inputs_datum = Datum([tx_mnt_ten_hash, bytes([sectionType.MINT_OUTPUTS.value]), bytearray(b"\x00\x00\x00\x00")])
inputs_section = Section(sectionType.INPUTS, [inputs_datum])
inputs_section_hash = hash_sha_256(inputs_section.sx_to_bytes())

sig = sign(mallory_sk, inputs_section_hash)

hash_datum = Datum([inputs_section_hash])
sig_datum = Datum([mallory_vk.to_string(), sig])
sig_section = Section(sectionType.SIGNATURES, [hash_datum, sig_datum])

tx = Transaction([inputs_section, sig_section])

if(txHC.insert_tx(tx)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

print("\n\nBeginning Wildcard Test Suite...\n\n")

# The colors of coins we're gonna trade:
BTC = bytearray(b"\xbb\xbb\xbb\xbb" * 8)
ETH = bytearray(b"\xee\xee\xee\xee" * 8)

# 'f' is for 'fraud'
QRK = bytearray(b"\xff\xff\xff\xff" * 8)

# Alice authorizes herself to mint BTC
print(BTC)
color_datum = Datum([BTC])
color_section = Section(sectionType.COINCOLOR, [color_datum])

nonce = txHC.generate_unused_nonce()
nonce_datum = Datum([nonce])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

authed_datum = Datum([bytearray(alice_ad)])
authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum])

tx = Transaction([nonce_section, color_section, authed_section])
tx_hash_00 = hash_sha_256(tx.tx_to_bytes())

if(txHC.insert_tx(tx)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Bob authorizes himself to mint ETH
color_datum = Datum([ETH])
color_section = Section(sectionType.COINCOLOR, [color_datum])

nonce = txHC.generate_unused_nonce()
nonce_datum = Datum([nonce])
nonce_section = Section(sectionType.NONCE, [nonce_datum])

authed_datum = Datum([bytearray(bob_ad)])
authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum])

tx = Transaction([nonce_section, color_section, authed_section])
tx_hash_01 = hash_sha_256(tx.tx_to_bytes())

if(txHC.insert_tx(tx)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Alice mints 2x BTC
nonce_datum = Datum([txHC.generate_unused_nonce()])
nonce_section = Section(sectionType.NONCE, [nonce_datum])
mint_outputs_datum = Datum([bytearray(alice_ad), BTC, bytearray(b"\x00\x02\x00\x00")])
mint_outputs_section = Section(sectionType.MINT_OUTPUTS, [mint_outputs_datum])

sig_bytes = bytes(mint_outputs_section.sx_to_bytes()) + bytes(nonce_section.sx_to_bytes())

sig_mnt_hash_sha_256 = Datum([hash_sha_256(sig_bytes)])

sig = sign(alice_sk, hash_sha_256(sig_bytes))

sig_mnt_datum = Datum([alice_vk.to_string(), sig, tx_hash_00])

sig_mnt_section = Section(sectionType.SIG_MINT, [sig_mnt_hash_sha_256, sig_mnt_datum])

tx = Transaction([mint_outputs_section, nonce_section, sig_mnt_section])
tx_hash_02 = hash_sha_256(tx.tx_to_bytes())

if(txHC.insert_tx(tx)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Bob mints 2x ETH
nonce_datum = Datum([txHC.generate_unused_nonce()])
nonce_section = Section(sectionType.NONCE, [nonce_datum])
mint_outputs_datum = Datum([bytearray(bob_ad), ETH, bytearray(b"\x00\x02\x00\x00")])
mint_outputs_section = Section(sectionType.MINT_OUTPUTS, [mint_outputs_datum])

sig_bytes = bytes(mint_outputs_section.sx_to_bytes()) + bytes(nonce_section.sx_to_bytes())

sig_mnt_hash_sha_256 = Datum([hash_sha_256(sig_bytes)])

sig = sign(bob_sk, hash_sha_256(sig_bytes))

sig_mnt_datum = Datum([bob_vk.to_string(), sig, tx_hash_01])

sig_mnt_section = Section(sectionType.SIG_MINT, [sig_mnt_hash_sha_256, sig_mnt_datum])

tx = Transaction([mint_outputs_section, nonce_section, sig_mnt_section])
tx_hash_03 = hash_sha_256(tx.tx_to_bytes())

if(txHC.insert_tx(tx)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Bob trades his 2 ETH for Alice's 2 BTC
inputs_datum = Datum([tx_hash_03, bytes([sectionType.MINT_OUTPUTS.value]), bytearray(b"\x00\x00\x00\x00")])
inputs_section = Section(sectionType.INPUTS, [inputs_datum])

outputs_datum = Datum([bob_ad, BTC, bytearray(b"\x00\x02\x00\x00")])
outputs_section = Section(sectionType.OUTPUTS, [outputs_datum])

alice_pseudonym = bytearray(os.urandom(32))
wildcard_outputs_datum = Datum([alice_pseudonym, ETH, bytearray(b"\x00\x02\x00\x00")])
wildcard_outputs_section = Section(sectionType.WILDCARD_OUTPUTS, [wildcard_outputs_datum])

tx_bytes = inputs_section.sx_to_bytes() + outputs_section.sx_to_bytes() + wildcard_outputs_section.sx_to_bytes()
running_tx_hash = hash_sha_256(tx_bytes)
sig = sign(bob_sk, running_tx_hash)

sig_hash_datum = Datum([running_tx_hash])
sig_datum = Datum([bob_vk.to_string(), sig])
sig_section = Section(sectionType.SIGNATURES, [sig_hash_datum, sig_datum])

wildcard_inputs_datum = Datum([tx_hash_02, bytes([sectionType.MINT_OUTPUTS.value]), bytearray(b"\x00\x00\x00\x00")])
wildcard_inputs_section = Section(sectionType.WILDCARD_INPUTS, [wildcard_inputs_datum])

wildcard_change_datum = Datum([alice_ad, BTC, bytearray(b"\x00\x00\x00\x00")])
wildcard_change_section = Section(sectionType.WILDCARD_CHANGE, [wildcard_change_datum])

wildcard_ids_datum = Datum([alice_pseudonym, alice_ad])
wildcard_ids_section = Section(sectionType.WILDCARD_ID, [wildcard_ids_datum])

tx_bytes += sig_section.sx_to_bytes() + wildcard_inputs_section.sx_to_bytes()
tx_bytes += wildcard_change_section.sx_to_bytes() + wildcard_ids_section.sx_to_bytes()
running_tx_hash = hash_sha_256(tx_bytes)
alice_sig = sign(alice_sk, running_tx_hash)

wildcard_sig_hash_datum = Datum([running_tx_hash])
wildcard_sig_datum = Datum([alice_vk.to_string(), alice_sig])
wildcard_sig_section = Section(sectionType.WILDCARD_SIGNATURES, [wildcard_sig_hash_datum, wildcard_sig_datum])

tx = Transaction([inputs_section, outputs_section, wildcard_outputs_section, sig_section, wildcard_inputs_section, wildcard_change_section, wildcard_ids_section, wildcard_sig_section])

tx_hash_04 = hash_sha_256(tx.tx_to_bytes())

if(txHC.insert_tx(tx)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

print("\n\nTest suites finished! Beginning fuzzing procedure...\n\n")
exit(1)

# Fuzzing
tx = random_tx()

while(not txHC.insert_tx(tx)):
    tx = random_tx()

# If we got here, then that means that a transaction was accepted -- i.e.
# something about the TVF is wrong... so we print the transaction
tx.tx_print()
