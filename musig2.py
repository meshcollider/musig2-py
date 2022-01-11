import hashlib
import os.path
import secrets
import sys
from typing import Tuple, Optional, Any

# secp256k1 finite field order (p) and group order (n)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Points are tuples of X and Y coordinates and the point at infinity is
# represented by the None keyword.
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# Number of nonces used by each signer. 2 is proven secure for AGM + AOMDL
# 4 is proven secure for just AOMDL assumption.
nu = 2

SECRET_KEY_FILE = 'secret.key'
PUBLIC_KEY_LIST_FILE = 'public_keys'
SECRET_NONCE_FILE = 'secret_nonces'
PUBLIC_NONCE_LIST_FILE = 'public_nonces'

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

# This uses BIP-340's tagged hash, SHA256(SHA256(tag) || SHA256(tag) || x)
def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

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

def aggregate_public_keys(own_key: Optional[bytes] = None, negate: bool = False) -> Tuple[bytes, int]:
    public_keys_to_aggregate = read_bytes_from_hex_list(PUBLIC_KEY_LIST_FILE)
    if not public_keys_to_aggregate:
        print("Error: need at least one public key.")
        quit()
    num_keys = len(public_keys_to_aggregate)
    if not negate:
        print(f"Aggregating {num_keys} public key{'s' if num_keys > 1 else ''}...")
    aggregate_key = None
    a_1 = 0
    for kb in public_keys_to_aggregate:
        a_i = key_agg_coeff(public_keys_to_aggregate, kb)
        if negate:
            a_i = n - a_i
        if own_key == kb:
            a_1 = a_i
        pubkey_i = lift_x(kb)
        if not pubkey_i:
            print(f"Error: Public key {kb.hex()} is invalid.")
            quit()
        a_i_pk = point_mul(pubkey_i, a_i)
        aggregate_key = point_add(aggregate_key, a_i_pk)
    assert not is_infinite(aggregate_key)
    if not has_even_y(aggregate_key):
        # If we have already tried negating the coefficients then something has definitely gone wrong
        assert not negate
        print("Aggregate key has odd y, repeating with negated coefficients")
        return aggregate_public_keys(own_key, True)
    aggregate_key_bytes = bytes_from_point(aggregate_key)
    assert aggregate_key_bytes
    print(f"Aggregate public key: {aggregate_key_bytes.hex()}")
    return aggregate_key_bytes, a_1

def aggregate_nonces(nonce_list: list[list[bytes]]) -> list[Point]:
    aggregated_nonces = []
    for j in range(nu):
        R_j = None
        for nonces in nonce_list:
            point = lift_x(nonces[j])
            R_j = point_add(R_j, point)
        aggregated_nonces.append(R_j)
    return aggregated_nonces

def hash_nonces(agg_pubkey: bytes, nonces: list[Point], msg: bytes) -> int:
    bytes_to_hash = agg_pubkey
    for nonce in nonces:
        bytes_to_hash += bytes_from_point(nonce)
    bytes_to_hash += msg
    hash_bytes = tagged_hash("musig2/non", bytes_to_hash)
    return int_from_bytes(hash_bytes)

def compute_R(nonces: list[Point], b: int) -> Point:
    R = None
    for j in range(nu):
        R_j = point_mul(nonces[j], b**j)
        R = point_add(R, R_j)
    assert not is_infinite(R)
    return R

def participant_sign(chall: int, secret: bytes, coeff: int, nonce_secrets: list[bytes], b: int, negate: bool = False) -> int:
    s = chall * coeff
    s *= int_from_bytes(secret)
    s %= n
    for j in range(nu):
        r_1j = int_from_bytes(nonce_secrets[j])
        if negate:
            r_1j = n - r_1j
        s += (r_1j * b**j)
        s %= n
    return s

def chall_hash(agg_pubkey: bytes, R: bytes, msg: bytes) -> int:
    bytes_to_hash = b'' + agg_pubkey + R + msg
    hash_bytes = tagged_hash("musig2/sig", bytes_to_hash)
    return int_from_bytes(hash_bytes)

def verify_sig(aggregate_key_bytes: bytes, msg: bytes, R_bytes: bytes, s: int) -> bool:
    left = point_mul(G, s)
    R = lift_x(R_bytes)
    aggregate_key = lift_x(aggregate_key_bytes)
    c = chall_hash(aggregate_key_bytes, R_bytes, msg)
    right = point_add(R, point_mul(aggregate_key, c))
    return left == right

def write_bytes(bytes_to_write: bytes, filename: str) -> bool:
    if os.path.isfile(filename):
        print(f"File {filename} already exists, will not overwrite.")
        return False
    with open(filename, 'wb') as f:
        return f.write(bytes_to_write) > 0

def read_bytes(filename: str) -> bytes:
    if not os.path.isfile(filename):
        print(f"Error: file {filename} does not exist.")
        return None
    with open(filename, 'rb') as f:
        read_bytes =  f.read()
        return read_bytes if len(read_bytes) > 0 else None

def read_bytes_from_hex_list(filename: str) -> list[bytes]:
    if not os.path.isfile(filename):
        print(f"Error: file {filename} does not exist.")
        return None
    hex_list = []
    with open(filename, 'r') as f:
        for line in f:
            hex_bytes = bytes.fromhex(line)
            hex_list.append(hex_bytes)
    return hex_list


def main():
    if len(sys.argv) < 2:
        print("Available commands: keygen, noncegen, aggregatekeys, sign, aggregatesignature, verify")
        quit()

    command = sys.argv[1]

    # Generate a publib + private keypair
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
        for j in range(nu):
            r_1j = seckey_gen()
            R_1j = pubkey_gen(r_1j)
            nonce_secrets.append(r_1j)
            nonces.append(R_1j)
            print(R_1j.hex())
        nonce_byte_string = b'\n'.join(nonce_secrets)
        write_bytes(nonce_byte_string, SECRET_NONCE_FILE)
        quit()

    # Compute the aggregate public key
    elif command == "aggregatekeys":
        aggregate_public_keys()
        quit()

    elif command == "sign":
        message_file = 'message' if len(sys.argv) < 3 else sys.argv[2]
        message = read_bytes(message_file)
        if not message:
            quit()

        seckey = read_bytes(SECRET_KEY_FILE)
        if not seckey:
            quit()
        pubkey = pubkey_gen(seckey)

        # Aggregate the nonces from all participants
        nonces_to_aggregate = read_bytes_from_hex_list(PUBLIC_NONCE_LIST_FILE)
        if not nonces_to_aggregate:
            quit()
        # Every nu nonces are a set corresponding to one signer
        nonces_to_aggregate_split = [nonces_to_aggregate[i:i + nu] for i in range(0, len(nonces_to_aggregate), nu)]
        aggregated_nonces = aggregate_nonces(nonces_to_aggregate_split)
        (aggregate_key, a_1) = aggregate_public_keys(pubkey)

        nonce_secret_bytes = read_bytes(SECRET_NONCE_FILE)
        if not nonce_secret_bytes:
            quit()
        nonce_secrets = nonce_secret_bytes.split(b'\n')

        # Compute R
        b = hash_nonces(aggregate_key, aggregated_nonces, message)
        R = compute_R(aggregated_nonces, b)

        # Compute challenge
        c = chall_hash(aggregate_key, bytes_from_point(R), message)

        # Sign
        s_1 = participant_sign(c, seckey, a_1, nonce_secrets, b, not has_even_y(R))

        print(f"Partial signature s_1: {s_1}")
        R_bytes = bytes_from_point(R)
        print(f"Signature R: {R_bytes.hex()}")

    elif command == "aggregatesignature":
        s = 0
        with open('s_values', 'r') as f:
            for s_i in f:
                s += int(s_i)
                s %= n
        print(f"Signature s: {s}")

    elif command == "verify":
        if len(sys.argv) < 5:
            print("Usage: verify [pubkey] [R] [s] [message_file]")
            quit()
        pubkey = bytes.fromhex(sys.argv[2])
        R = bytes.fromhex(sys.argv[3])
        s = int(sys.argv[4])
        message_file = 'message' if len(sys.argv) < 6 else sys.argv[5]
        message = read_bytes(message_file)

        valid = verify_sig(pubkey, message, R, s)
        print(f"Signature is valid: {valid}")

    else:
        print("Unknown command.")
        quit()

if __name__ == "__main__":
    main()
