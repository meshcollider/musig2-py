import musig2 as m2

import hashlib
import struct
import sys

# From PyBitcoin
def to_varint(i):
    if i < (2**8-3):
        return chr(i) # pack the integer into one byte
    elif i < (2**16):
        return chr(253) + struct.pack('<H', i) # pack into 2 bytes
    elif i < (2**32):
        return chr(254) + struct.pack('<I', i) # pack into 4 bytes
    elif i < (2**64):
        return chr(255) + struct.pack('<Q', i) # pack into 8 bites
    else:
        raise Exception('Integer cannot exceed 8 bytes in length.')

def from_varint(bs):
    if bs[0] < (2**8-3):
        return bs[0], 1
    elif bs[0] == 253:
        return struct.unpack('<H', bs[1:2]), 2
    elif bs[0] == 254:
        return struct.unpack('<I', bs[1:4]), 4
    elif bs[0] == 255:
        return struct.unpack('<Q', bs[1:8]), 8

# given the bytes of a bitcoin transaction, decode it
def decode_raw_tx(tx):
    segwit = True
    version = tx[0:4]
    marker = tx[4]
    flag = tx[5]
    if marker != 0 or flag != 1:
        segwit = False
    ind = 6 if segwit else 4
    num_inputs = tx[ind]
    ind += 1
    inputs = []
    for _ in range(num_inputs):
        # outpoint = 32 byte hash + 4 byte output index
        outpoint = tx[ind:ind+36]
        ind += 36
        scriptSigLength = tx[ind]
        if scriptSigLength != 0:
            print("Error: transaction already has signature")
            quit()
        ind += 1
        sequence = tx[ind:ind+4]
        ind += 4
        inputs.append((outpoint, sequence))
    num_outputs = tx[ind]
    ind += 1
    outputs = []
    for _ in range(num_outputs):
        amount = tx[ind:ind+8]
        ind += 8
        scriptPubKeyLen, inc = from_varint(tx[ind:ind+9])
        ind += inc
        scriptPubKey = tx[ind:ind+scriptPubKeyLen]
        outputs.append((scriptPubKey, amount))
        ind += scriptPubKeyLen
    locktime = tx[ind:ind+4]
    return (version, inputs, outputs, locktime)

def SigMsg(tx, amount_bytes, spk_bytes, input_index):
    hash_type = b'\x00'
    (version, inputs, outputs, locktime) = decode_raw_tx(tx)

    if len(inputs) != len(amount_bytes) or len(inputs) != len(spk_bytes):
        print("Error: mismatch between length of inputs, amounts, and scriptPubKeys.")
        quit()

    sigmsg = hash_type + version + locktime
    prevouts = b''
    amounts = b''.join(amount_bytes)
    spks = b''.join(spk_bytes)
    sequences = b''
    for (outpoint, sequence) in inputs:
        prevouts += outpoint
        sequences += sequence
    sha_prevouts = hashlib.sha256(prevouts).digest()
    sha_amounts = hashlib.sha256(amounts).digest()
    sha_scriptpubkeys = hashlib.sha256(spks).digest()
    sha_sequences = hashlib.sha256(sequences).digest()

    sigmsg += sha_prevouts + sha_amounts + sha_scriptpubkeys + sha_sequences

    outputs = b''
    for (scriptPubKey, amount) in outputs:
        outputs += amount + scriptPubKey

    sha_outputs = hashlib.sha256(outputs).digest()
    sigmsg += sha_outputs
    sigmsg += b'\x00' # spend type
    sigmsg += input_index.to_bytes(4, byteorder="little")

    print(sigmsg.hex())
    return sigmsg


def main():
    if len(sys.argv) < 2:
        print("Available commands: tx2msg, addsig")
        quit()

    command = sys.argv[1]

    # Given a hex-encoded bitcoin transaction, generate the message to sign with musig2
    if command == "tx2msg":
        if len(sys.argv) != 6:
            print("Usage: tx2msg [tx_hex] [amounts] [scriptPubKeys] [input index]")
            print("Amounts should be a CSV list of hex-encoded amounts being spent, in satoshis, each 8-bytes in little-endian format. The order should match the order of the inputs.")
            print("scriptPubKeys should be a CSV list of hex-encoded scriptPubKeys of the input outpoints, in order.")
        tx_bytes = bytes.fromhex(sys.argv[2])
        amounts_hex = sys.argv[3].split(',')
        amounts_bytes = []
        for amount in amounts_hex:
            amounts_bytes.append(bytes.fromhex(amount.strip()))
        spks_hex = sys.argv[4].split(',')
        spk_bytes = []
        for spk in spks_hex:
            spk_bytes.append(bytes.fromhex(spk.strip()))
        input_index = int(sys.argv[5])
        msg = SigMsg(tx_bytes, amounts_bytes, spk_bytes, input_index)
        m2.write_bytes(msg, 'message')




    else:
        print("Unknown command.")
        quit()

if __name__ == "__main__":
    main()
