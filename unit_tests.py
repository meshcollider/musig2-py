import musig2 as m2

import random
import os
import sys

def test_seckey_gen():
    for _ in range(10):
        key = m2.seckey_gen()
        pubkey = m2.pubkey_gen(key)
        assert pubkey is not None
        key_int = m2.int_from_bytes(key)
        pubkey_check = m2.point_mul(m2.G, key_int)
        assert m2.has_even_y(pubkey_check)
        assert m2.lift_x(m2.bytes_from_point(pubkey_check)) == pubkey_check
        assert m2.bytes_from_point(pubkey_check) == pubkey
    print("test_seckey_gen PASSED")

def test_read_write_bytes():
    for _ in range(10):
        bytes = random.randbytes(32)
        m2.write_bytes(bytes, 'test_read_write')
        read_bytes = m2.read_bytes('test_read_write')
        assert bytes == read_bytes
        os.remove('test_read_write')

        bytes_list = [random.randbytes(32) for _ in range(10)]
        assert m2.write_bytes_list_to_hex(bytes_list, 'test_read_hex_list')
        read_bytes_list = m2.read_bytes_from_hex_list('test_read_hex_list')
        assert read_bytes_list == bytes_list
        os.remove('test_read_hex_list')
    print("test_read_write_bytes PASSED")

def test_aggregate_public_keys():
    for _ in range(5):
        secrets = []
        pubkeys = []
        coeffs = []
        for _ in range(5):
            sec_i = m2.seckey_gen()
            secrets.append(sec_i)
            pub_i = m2.pubkey_gen(sec_i)
            pubkeys.append(pub_i)
        with open('test_aggregate_public_keys', 'w') as f:
                for k in pubkeys:
                    f.write(k.hex() + '\n')
        public_keys_list = m2.read_bytes_from_hex_list('test_aggregate_public_keys')
        combined_key = None
        for k in pubkeys:
            ck, coeff_i = m2.aggregate_public_keys(public_keys_list, k, False)
            if combined_key is None:
                combined_key = ck
            else:
                assert combined_key == ck
            coeffs.append(coeff_i)
        assert not m2.is_infinite(combined_key)
        combined_sec = 0
        for sec, coeff in zip(secrets, coeffs):
            combined_sec += m2.int_from_bytes(sec) * coeff
            combined_sec %= m2.n
        pubkey_check = m2.point_mul(m2.G, combined_sec)
        assert m2.has_even_y(pubkey_check)
        assert m2.bytes_from_point(pubkey_check) == combined_key
        os.remove('test_aggregate_public_keys')
        sys.stdout.write('.')
        sys.stdout.flush()
    sys.stdout.write('\rtest_aggregate_public_keys PASSED\n')
    sys.stdout.flush()
    #print("test_aggregate_public_keys PASSED")

def test_aggregate_nonces():
    for _ in range(5):
        nonce_secrets = []
        nonces = []
        aggregated_nonces = [None for _ in range(m2.nu)]
        for _ in range(5):
            for ind in range(m2.nu):
                r_1j = m2.seckey_gen()
                R_1j = m2.pubkey_gen(r_1j)
                R_1j_check = m2.point_mul(m2.G, m2.int_from_bytes(r_1j))
                assert R_1j_check == m2.lift_x(R_1j)
                nonce_secrets.append(r_1j)
                nonces.append(R_1j)
                aggregated_nonces[ind] = m2.point_add(aggregated_nonces[ind], R_1j_check)
        assert m2.write_bytes_list_to_hex(nonce_secrets, 'test_aggregate_nonces')
        nonce_secrets_check = m2.read_bytes_from_hex_list('test_aggregate_nonces')
        os.remove('test_aggregate_nonces')
        assert nonce_secrets_check == nonce_secrets
        aggregate_nonce_points = m2.aggregate_nonces(nonces)
        assert aggregate_nonce_points == aggregated_nonces
        sys.stdout.write('.')
        sys.stdout.flush()
    sys.stdout.write('\rtest_aggregate_nonces PASSED\n')
    sys.stdout.flush()

def test_compute_R():
    for _ in range(5):
        random_privkey = m2.seckey_gen()
        random_pubkey = m2.pubkey_gen(random_privkey)
        nonces = []
        nonce_secrets = []
        # Simulate 5 participants, each with nu nonces
        for _ in range(5):
            for _ in range(m2.nu):
                r_1j = m2.seckey_gen()
                R_1j = m2.pubkey_gen(r_1j)
                nonce_secrets.append(r_1j)
                nonces.append(R_1j)
        aggregate_nonce_points = m2.aggregate_nonces(nonces)
        b = m2.hash_nonces(random_pubkey, aggregate_nonce_points, b'hello world')
        R, negated = m2.compute_R(aggregate_nonce_points, b, False)

        secret_check = 0
        for p in range(5):
            for n in range(m2.nu):
                secret_check += m2.int_from_bytes(nonce_secrets[m2.nu*p + n]) * (b**n)
                secret_check %= m2.n

        R_check = m2.point_mul(m2.G, secret_check)
        assert m2.bytes_from_point(R) == m2.bytes_from_point(R_check)
        if negated:
            assert not m2.has_even_y(R_check)
            assert R != R_check
        else:
            assert m2.has_even_y(R_check)
            assert R == R_check

        sys.stdout.write('.')
        sys.stdout.flush()
    sys.stdout.write('\rtest_compute_R PASSED\n')
    sys.stdout.flush()


if __name__ == "__main__":
    test_seckey_gen()
    test_read_write_bytes()
    test_compute_R()
    test_aggregate_nonces()
    test_aggregate_public_keys()
