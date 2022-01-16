import hashlib
import os
import secrets
import sys
from typing import Tuple, Optional

# secp256k1 finite field order (p) and group order (n)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Points are tuples of X and Y coordinates and the point at infinity is
# represented by the None keyword.
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# Number of nonces used by each signer. 2 is proven secure for AGM + AOMDL
# 4 is proven secure for just AOMDL assumption.
nu = 2

########## POINT FUNCTIONS ##########

Point = Tuple[int, int]

def is_infinite(P: Optional[Point]) -> bool:
    return P is None

def x(P: Point) -> int:
    assert not is_infinite(P)
    return P[0]

def y(P: Point) -> int:
    assert not is_infinite(P)
    return P[1]

def has_even_y(P: Point) -> bool:
    return y(P) & 1 == 0

def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if (x(P1) == x(P2)) and (y(P1) != y(P2)):
        return None
    if P1 == P2:
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return (x3, (lam * (x(P1) - x3) - y(P1)) % p)

def point_mul(P: Optional[Point], n: int) -> Optional[Point]:
    R = None
    for i in range(256):
        if (n >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")

def bytes_from_point(P: Point, compressed: bool = False) -> bytes:
    x_coord = bytes_from_int(x(P))
    if compressed:
        if has_even_y(P):
            return b'\x02' + x_coord
        else:
            return b'\x03' + x_coord
    return x_coord

def lift_x(b: bytes) -> Optional[Point]:
    if len(b) == 32:
        x = int_from_bytes(b)
        even = True
    else:
        x = int_from_bytes(b[1:])
        even = (b[0] == 2)
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    if (even and y & 1 != 0) or ((not even) and y & 1 == 0):
        y = p - y
    return (x, y)

def pubkey_gen(seckey: bytes, compressed: bool = False) -> bytes:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return bytes_from_point(P, compressed)

def seckey_gen() -> bytes:
    # choose random integer below the order of the curve
    seckey_int = secrets.randbelow(n)
    # Check that this int gives a public key with even y
    P = point_mul(G, seckey_int)
    if not has_even_y(P):
        seckey_int = n - seckey_int
    # Convert it to bytes
    seckey_bytes = bytes_from_int(seckey_int)
    # Return the secret key
    return seckey_bytes

########## FILE FUNCTIONS ##########

SECRET_KEY_FILE = 'secret.key'
PUBLIC_KEY_LIST_FILE = 'public_keys'
SECRET_NONCE_FILE = 'secret_nonces'
PUBLIC_NONCE_LIST_FILE = 'public_nonces'
DEFAULT_MESSAGE_FILE = 'message'
S_VALUES_FILE = 's_values'

def write_bytes(bytes_to_write: bytes, filename: str) -> bool:
    if os.path.isfile(filename):
        print(f"File {filename} already exists, will not overwrite.")
        return False
    with open(filename, 'wb') as f:
        return f.write(bytes_to_write) > 0

def read_bytes(filename: str) -> bytes:
    if not os.path.isfile(filename):
        print(f"Error: file {filename} does not exist.")
        quit()
    with open(filename, 'rb') as f:
        read_bytes = f.read()
    if len(read_bytes) <= 0:
        print(f"Error: file {filename} is empty.")
        quit()
    return read_bytes

def write_bytes_list_to_hex(bytes_list: list[bytes], filename: str) -> bool:
    if os.path.isfile(filename):
        os.remove(filename)
    with open(filename, 'w') as f:
        for byte_string in bytes_list:
            if not f.write(f"{byte_string.hex()}\n") > 0:
                return False
    return True

def read_bytes_from_hex_list(filename: str) -> list[bytes]:
    if not os.path.isfile(filename):
        print(f"Error: file {filename} does not exist.")
        quit()
    hex_list = []
    with open(filename, 'r') as f:
        for line in f:
            hex_bytes = bytes.fromhex(line)
            hex_list.append(hex_bytes)
    if not hex_list:
        print(f"Error: file {filename} is empty.")
        quit()
    return hex_list

def get_message(filename: str) -> bytes:
    message = read_bytes(filename)
    if not message:
        quit()
    return message

########## HELPER FUNCTIONS ##########

# This uses BIP-340's tagged hash, SHA256(SHA256(tag) || SHA256(tag) || x)
def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

# Returns true if public_key is the second unique key in key_list
def is_second_unique_key(key_list, public_key):
    for key in key_list:
        if key != key_list[0]:
            if key == public_key:
                return True
            else:
                return False
    return False

# Takes a list of public keys, and another key, and creates the aggregation coefficient for that key
def key_agg_coeff(key_set: list[bytes], public_key: bytes) -> int:
    # Sort the set of keys in lexicographical order
    sorted_keys = sorted(key_set)
    # If this is the second unique key in the list, we optimise by using coefficient 1
    if is_second_unique_key(sorted_keys, public_key):
        return 1
    # Compute the hash of the sorted key list
    L = tagged_hash("KeyAgg list", b''.join(sorted_keys))
    hash_bytes = tagged_hash("KeyAgg coefficient", L + public_key)
    # Convert the coefficient to an integer modulo the curve order
    coefficient = int_from_bytes(hash_bytes) % n
    return coefficient

########## MUSIG2 FUNCTIONS ##########

def aggregate_public_keys(public_key_list: list[bytes], own_key: Optional[bytes]) -> Tuple[Point, int]:
    aggregate_key = None
    own_coeff = 0
    for key_bytes in public_key_list:
        # a_i is an integer coefficient
        a_i = key_agg_coeff(public_key_list, key_bytes)
        # If this key is the one specified, save the coefficient to return
        # This also ensures the key specified is actually part of the list
        if own_key == key_bytes:
            own_coeff = a_i
        # All the public keys should have implicitly even y coordinates
        pubkey_i = lift_x(key_bytes)
        if not pubkey_i:
            print(f"Error: Public key {key_bytes.hex()} is invalid.")
            quit()
        # Multiply the key by its coefficient
        a_i_pk = point_mul(pubkey_i, a_i)
        # Add the resulting point to our sum
        aggregate_key = point_add(aggregate_key, a_i_pk)
        assert not is_infinite(aggregate_key)
    if own_key is not None:
        assert own_coeff > 0
    return aggregate_key, own_coeff

def aggregate_nonces(nonces_to_aggregate: list[bytes]) -> list[Point]:
    # Every nu nonces are a set corresponding to one signer
    aggregated_nonces = []
    for j in range(nu):
        R_j = None
        for combined_nonce in nonces_to_aggregate:
            nonce_component = combined_nonce[33*j : 33*(j + 1)]
            point = lift_x(nonce_component)
            R_j = point_add(R_j, point)
        if is_infinite(R_j):
            # From spec: there is at least one dishonest signer (except with negligible probability).
            # Continue with arbitrary use of point G so the dishonest signer can be caught later
            R_j = G
        aggregated_nonces.append(R_j)
    return aggregated_nonces

def hash_nonces(agg_pubkey: bytes, nonces: list[bytes], msg: bytes) -> int:
    bytes_to_hash = b''.join(nonces) + agg_pubkey + msg
    hash_bytes = tagged_hash("MuSig/noncecoef", bytes_to_hash)
    b = int_from_bytes(hash_bytes) % n
    return b

def chall_hash(agg_pubkey: bytes, R: bytes, msg: bytes) -> int:
    bytes_to_hash = b'' + R + agg_pubkey + msg
    # Use the BIP-340 challenge hash so the final signature is a valid BIP-340 schnorr signature
    hash_bytes = tagged_hash("BIP0340/challenge", bytes_to_hash)
    return int_from_bytes(hash_bytes)

def compute_R(nonces: list[Point], b: int) -> Point:
    R = None
    for j in range(nu):
        R_j = point_mul(nonces[j], (b**j) % n)
        R = point_add(R, R_j)
    assert not is_infinite(R)
    return R

def compute_s(chall: int, secret: bytes, coeff: int, nonce_secrets: list[bytes], b: int) -> int:
    # s = c*a_1*x_1 + \sum{ r_1,j * b^{j-1} }
    s = (chall * coeff * int_from_bytes(secret)) % n
    for j in range(nu):
        r_1j = int_from_bytes(nonce_secrets[j])
        b_coeff = (b**j) % n
        s += (r_1j * b_coeff)
        s %= n
    return s

def verify_sig(aggregate_key_bytes: bytes, msg: bytes, R_bytes: bytes, s: int) -> bool:
    left = point_mul(G, s)
    R = lift_x(R_bytes)
    aggregate_key = lift_x(aggregate_key_bytes)
    c = chall_hash(aggregate_key_bytes, R_bytes, msg)
    right = point_add(R, point_mul(aggregate_key, c))
    return left == right


def main():
    if len(sys.argv) < 2:
        print("Available commands: keygen, noncegen, aggregatekeys, sign, aggregatesignature, verify")
        quit()

    command = sys.argv[1]

    # Generate a public + private keypair
    if command == "keygen":
        seckey = seckey_gen()
        if not write_bytes(seckey, SECRET_KEY_FILE):
            seckey = read_bytes(SECRET_KEY_FILE)
        pubkey = pubkey_gen(seckey)
        print(f"Your public key:\n{pubkey.hex()}")
        quit()

    # Generate some random nonces
    elif command == "noncegen":
        nonce_secrets = []
        nonces = b''
        print("WARNING: Only use this nonce once, then generate a new one.")
        print("Reusing nonces to sign different messages will leak your secret key.")
        for _ in range(nu):
            # Generate a secret key
            r_1j = seckey_gen()
            # R_1j will be in 33-byte compressed key form with a parity byte
            R_1j = pubkey_gen(r_1j, compressed = True)
            # Add this newly generated keypair to the lists
            nonce_secrets.append(r_1j)
            nonces += R_1j
            # Print the public nonce
        print(f"Your new nonce:\n{nonces.hex()}")
        # Encode the nonce secrets as a newline-separated list
        write_bytes_list_to_hex(nonce_secrets, SECRET_NONCE_FILE)
        quit()

    # Compute the aggregate public key
    elif command == "aggregatekeys":
        public_keys_list = read_bytes_from_hex_list(PUBLIC_KEY_LIST_FILE)
        combined_key, _ = aggregate_public_keys(public_keys_list, None)
        combined_key_bytes = bytes_from_point(combined_key)
        print(f"Aggregate public key:\n{combined_key_bytes.hex()}")
        quit()

    # Generate a partial signature from our secret key w.r.t. the aggregated key and nonces
    elif command == "sign":
        if len(sys.argv) > 3:
            print("Usage: sign [message_filename (optional)]")
            quit()
        elif len(sys.argv) == 3:
            message_file = sys.argv[2]
        else:
            message_file = DEFAULT_MESSAGE_FILE
        message = get_message(message_file)
        seckey = read_bytes(SECRET_KEY_FILE)
        pubkey = pubkey_gen(seckey)

        # Compute the aggregate public key
        public_keys_list = read_bytes_from_hex_list(PUBLIC_KEY_LIST_FILE)
        combined_key, a_1 = aggregate_public_keys(public_keys_list, pubkey)
        combined_key_bytes = bytes_from_point(combined_key)
        print(f"Aggregate key:\n{combined_key_bytes.hex()}")

        # Aggregate the nonces from all participants and compute R
        public_nonce_list = read_bytes_from_hex_list(PUBLIC_NONCE_LIST_FILE)
        if len(public_nonce_list) != len(public_keys_list):
            print("Error: mismatch between number of nonces and number of public keys.")
            quit()
        aggregated_nonce_points = aggregate_nonces(public_nonce_list)
        aggregated_nonce_bytes = [bytes_from_point(R, compressed = True) for R in aggregated_nonce_points]
        b = hash_nonces(combined_key_bytes, aggregated_nonce_bytes, message)
        R = compute_R(aggregated_nonce_points, b)
        R_bytes = bytes_from_point(R)
        print(f"Signature R:\n{R_bytes.hex()}")

        # Compute challenge
        c = chall_hash(combined_key_bytes, R_bytes, message)

        # Sign
        nonce_secrets = read_bytes_from_hex_list(SECRET_NONCE_FILE)
        if not has_even_y(R):
            # Negate all the nonce secrets if the R value has an odd y coordinate
            nonce_secrets = [bytes_from_int(n - int_from_bytes(r)) for r in nonce_secrets]
        if not has_even_y(combined_key):
            seckey = bytes_from_int(n - int_from_bytes(seckey))
        s_1 = compute_s(c, seckey, a_1, nonce_secrets, b)
        s_1_bytes = bytes_from_int(s_1)
        print(f"Partial signature s_1:\n{s_1_bytes.hex()}")

        with open(f"{message_file}.partsig", "w") as f:
            f.write(f"{combined_key_bytes.hex()}\n{R_bytes.hex()}\n{s_1_bytes.hex()}\n")

        # Delete the nonce secrets to ensure they are not reused multiple times
        os.remove(SECRET_NONCE_FILE)
        quit()

    # Take a list of partial signatures and combine them into a valid signature under the aggregate public key
    elif command == "aggregatesignature":
        if len(sys.argv) > 3:
            print("Usage: aggregatesignature [message_filename (optional)]")
            quit()
        elif len(sys.argv) == 3:
            message_file = sys.argv[2]
        else:
            message_file = DEFAULT_MESSAGE_FILE
        message = get_message(message_file)

        # Sum the partial signature values from all signers
        s = 0
        sig_bytes_list = read_bytes_from_hex_list(S_VALUES_FILE)
        for s_i in sig_bytes_list:
                s += int_from_bytes(s_i)
                s %= n
        s_bytes = bytes_from_int(s)

        # Retrieve the R value from the partsig file
        partsig_bytes_list = read_bytes_from_hex_list(f"{message_file}.partsig")
        R_bytes = partsig_bytes_list[1]
        # Combine to produce the final signature
        signature_bytes = R_bytes + s_bytes
        print(f"Hex-encoded signature:\n{signature_bytes.hex()}")
        quit()

    elif command == "verify":
        if len(sys.argv) < 4 or len(sys.argv) > 5:
            print("Usage: verify [pubkey] [signature] [message_filename (optional)]")
            quit()

        pubkey = bytes.fromhex(sys.argv[2])
        if len(pubkey) != 32:
            print("Error: length of public key must be 32 bytes")
            quit()

        signature_bytes = bytes.fromhex(sys.argv[3])
        if len(signature_bytes) != 64:
            print("Error: length of signature must be 64 bytes")
            quit()

        if len(sys.argv) == 5:
            message_file = sys.argv[4]
        else:
            message_file = DEFAULT_MESSAGE_FILE
        message = get_message(message_file)

        R = signature_bytes[0:32]
        s = int_from_bytes(signature_bytes[32:64])

        valid = verify_sig(pubkey, message, R, s)
        print(f"Signature is valid: {valid}")

    else:
        print("Unknown command.")
        quit()

if __name__ == "__main__":
    main()
