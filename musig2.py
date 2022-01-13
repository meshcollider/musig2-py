import hashlib
import os.path
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

def bytes_from_point(P: Point) -> bytes:
    return bytes_from_int(x(P))

def lift_x(b: bytes) -> Optional[Point]:
    x = int_from_bytes(b)
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return (x, y if y & 1 == 0 else p-y)

def pubkey_gen(seckey: bytes) -> bytes:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return bytes_from_point(P)

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
MESSAGE_FILE = 'message'
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
        print(f"File {filename} already exists, will not overwrite.")
        return False
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

def get_message() -> bytes:
    message = read_bytes(MESSAGE_FILE)
    if not message:
        quit()
    return message

########## HELPER FUNCTIONS ##########

# This uses BIP-340's tagged hash, SHA256(SHA256(tag) || SHA256(tag) || x)
def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

# Takes a list of public keys, and another key, and creates the aggregation coefficient for that key
def key_agg_coeff(key_set: list[bytes], public_key: bytes) -> int:
    # Sort the set of keys in lexicographical order
    sorted_keys = sorted(key_set)
    # Join the list of bytes as one byte string
    key_set_bytes = b''.join(sorted_keys)
    # Append the public key this coefficient is for
    key_set_bytes += public_key
    # Compute the tagged hash of the keys
    hash_bytes = tagged_hash("musig2/agg", key_set_bytes)
    coefficient = int_from_bytes(hash_bytes)
    # Ensure that the coefficient is within the group order
    assert 1 <= coefficient and coefficient < n
    return coefficient

########## MUSIG2 FUNCTIONS ##########

def aggregate_public_keys(public_key_list: list[bytes], own_key: Optional[bytes], negate: bool) -> Tuple[bytes, int]:
    aggregate_key = None
    own_coeff = 0
    for key_bytes in public_key_list:
        # a_i is an integer coefficient
        a_i = key_agg_coeff(public_key_list, key_bytes)
        # negate defines whether we need to negate all the a_i coefficients
        # to ensure the resulting key has an even y coordinate
        if negate:
            a_i = n - a_i
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
    if not has_even_y(aggregate_key):
        # If we have already tried negating the coefficients then something has definitely gone wrong
        assert not negate
        return aggregate_public_keys(public_key_list, own_key, True)
    if own_key is not None:
        assert own_coeff > 0
    aggregate_key_bytes = bytes_from_point(aggregate_key)
    assert aggregate_key_bytes
    return aggregate_key_bytes, own_coeff

def aggregate_nonces(nonces_to_aggregate: list[bytes]) -> list[Point]:
    # Every nu nonces are a set corresponding to one signer
    nonce_list = [nonces_to_aggregate[i:i + nu] for i in range(0, len(nonces_to_aggregate), nu)]
    aggregated_nonces = []
    for j in range(nu):
        R_j = None
        for nonces in nonce_list:
            point = lift_x(nonces[j])
            R_j = point_add(R_j, point)
        assert not is_infinite(R_j)
        aggregated_nonces.append(R_j)
    return aggregated_nonces

def hash_nonces(agg_pubkey: bytes, nonces: list[Point], msg: bytes) -> int:
    bytes_to_hash = agg_pubkey
    for nonce in nonces:
        bytes_to_hash += bytes_from_point(nonce)
    bytes_to_hash += msg
    hash_bytes = tagged_hash("musig2/non", bytes_to_hash)
    return int_from_bytes(hash_bytes)

def chall_hash(agg_pubkey: bytes, R: bytes, msg: bytes) -> int:
    bytes_to_hash = b'' + agg_pubkey + R + msg
    # Use the BIP-340 challenge hash so the final signature is a valid BIP-340 schnorr signature
    hash_bytes = tagged_hash("BIP0340/challenge", bytes_to_hash)
    return int_from_bytes(hash_bytes)

def compute_R(nonces: list[Point], b: int, negate: bool = False) -> Tuple[Point, bool]:
    R = None
    for j in range(nu):
        coeff = (b**j) % n
        if negate:
            coeff = n - coeff
        R_j = point_mul(nonces[j], coeff)
        R = point_add(R, R_j)
    if not has_even_y(R):
        # If we derived an R with an odd y coordinate, repeat but negate everything
        return compute_R(nonces, b, True)
    assert not is_infinite(R)
    return R, negate

def compute_s(chall: int, secret: bytes, coeff: int, nonce_secrets: list[bytes], b: int, negate: bool = False) -> int:
    # s = c*a_1*x_1 + \sum{ r_1,j * b^{j-1} }
    s = (chall * coeff * int_from_bytes(secret)) % n
    for j in range(nu):
        r_1j = int_from_bytes(nonce_secrets[j])
        b_coeff = (b**j) % n
        if negate:
            b_coeff = n - b_coeff
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
        print(f"Your public key: {pubkey.hex()}")
        quit()

    # Generate some random nonces
    elif command == "noncegen":
        nonce_secrets = []
        nonces = []
        print("Your nonces:")
        for _ in range(nu):
            # Generate a secret key
            r_1j = seckey_gen()
            # R_1j will always have even y coordinate
            R_1j = pubkey_gen(r_1j)
            # Add this newly generated keypair to the lists
            nonce_secrets.append(r_1j)
            nonces.append(R_1j)
            # Print the public nonce
            print(R_1j.hex())
        # Encode the nonce secrets as a newline-separated list
        write_bytes_list_to_hex(nonce_secrets, SECRET_NONCE_FILE)
        quit()

    # Compute the aggregate public key
    elif command == "aggregatekeys":
        public_keys_list = read_bytes_from_hex_list(PUBLIC_KEY_LIST_FILE)
        combined_key, _ = aggregate_public_keys(public_keys_list, None, False)
        print(f"Aggregate public key: {combined_key.hex()}")
        quit()

    # Generate a partial signature from our secret key w.r.t. the aggregated key and nonces
    elif command == "sign":
        message = get_message()
        seckey = read_bytes(SECRET_KEY_FILE)
        pubkey = pubkey_gen(seckey)

        # Compute the aggregate public key
        public_keys_list = read_bytes_from_hex_list(PUBLIC_KEY_LIST_FILE)
        combined_key, a_1 = aggregate_public_keys(public_keys_list, pubkey, False)

        print(f"Aggregate key: {combined_key.hex()}")

        # Aggregate the nonces from all participants
        public_nonce_list = read_bytes_from_hex_list(PUBLIC_NONCE_LIST_FILE)
        aggregated_nonce_points = aggregate_nonces(public_nonce_list)

        nonce_secrets = read_bytes_from_hex_list(SECRET_NONCE_FILE)

        # Compute R
        b = hash_nonces(combined_key, aggregated_nonce_points, message)
        R, negated = compute_R(aggregated_nonce_points, b)

        # Compute challenge
        c = chall_hash(combined_key, bytes_from_point(R), message)

        R_bytes = bytes_from_point(R)
        print(f"Signature R: {R_bytes.hex()}")

        # Sign
        s_1 = compute_s(c, seckey, a_1, nonce_secrets, b, negated)
        s_1_bytes = bytes_from_int(s_1)
        print(f"Partial signature s_1: {s_1_bytes.hex()}")
        quit()

    # Take a list of partial signatures and combine them into a valid signature under the aggregate public key
    elif command == "aggregatesignature":
        # Sum the partial signature values from all signers
        s = 0
        s_bytes_list = read_bytes_from_hex_list(S_VALUES_FILE)
        for s_i in s_bytes_list:
                s += int_from_bytes(s_i)
                s %= n
        s_bytes = bytes_from_int(s)

        # Get the message
        message = get_message()

        # Generate the aggregated nonce points from the nonce list
        public_nonce_list = read_bytes_from_hex_list(PUBLIC_NONCE_LIST_FILE)
        aggregated_nonce_points = aggregate_nonces(public_nonce_list)

        # Generate the aggregate public key from the public key list
        public_keys_list = read_bytes_from_hex_list(PUBLIC_KEY_LIST_FILE)
        combined_key, _ = aggregate_public_keys(public_keys_list, None, False)

        # Compute R
        b = hash_nonces(combined_key, aggregated_nonce_points, message)
        (R, _) = compute_R(aggregated_nonce_points, b)
        R_bytes = bytes_from_point(R)

        # Combine to produce the final signature
        signature_bytes = R_bytes + s_bytes
        print(f"Hex-encoded signature: {signature_bytes.hex()}")
        quit()

    elif command == "verify":
        if len(sys.argv) < 4:
            print("Usage: verify [pubkey] [signature]")
            quit()

        pubkey = bytes.fromhex(sys.argv[2])
        if len(pubkey) != 32:
            print("Error: length of public key must be 32 bytes")
            quit()

        signature_bytes = bytes.fromhex(sys.argv[3])
        if len(signature_bytes) != 64:
            print("Error: length of signature must be 64 bytes")
            quit()

        message = get_message()

        R = signature_bytes[0:32]
        s = int_from_bytes(signature_bytes[32:64])

        valid = verify_sig(pubkey, message, R, s)
        print(f"Signature is valid: {valid}")

    else:
        print("Unknown command.")
        quit()

if __name__ == "__main__":
    main()
