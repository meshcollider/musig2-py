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
        sys.stdout.write('.')
        sys.stdout.flush()
    sys.stdout.write('\rtest_seckey_gen PASSED\n')
    sys.stdout.flush()

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
        sys.stdout.write('.')
        sys.stdout.flush()
    sys.stdout.write('\rtest_read_write_bytes PASSED\n')
    sys.stdout.flush()

def test_point_serialisation():
    for _ in range(10):
        seckey = m2.seckey_gen()
        pubkey = m2.pubkey_gen(seckey)
        pubkey_point = m2.lift_x(pubkey)
        xonly_pubkey = m2.bytes_from_point(pubkey_point)
        assert xonly_pubkey == pubkey

        seckey = m2.seckey_gen(force_even_y=False)
        pubkey = m2.pubkey_gen(seckey, compressed=True)
        pubkey_point = m2.lift_x(pubkey)
        pubkey_check = m2.point_mul(m2.G, m2.int_from_bytes(seckey))
        assert pubkey_check == pubkey_point
        compressed_pubkey = m2.bytes_from_point(pubkey_point, compressed=True)
        assert compressed_pubkey == pubkey
        xonly_pubkey = m2.bytes_from_point(pubkey_point)
        assert xonly_pubkey == compressed_pubkey[1:]

        sys.stdout.write('.')
        sys.stdout.flush()
    sys.stdout.write('\rtest_point_serialisation PASSED\n')
    sys.stdout.flush()

def test_aggregate_public_keys():
    for _ in range(5):
        secrets = []
        pubkeys = []
        coeffs = []
        for _ in range(5):
            sec_i = m2.seckey_gen()
            secrets.append(m2.int_from_bytes(sec_i))
            pub_i = m2.pubkey_gen(sec_i)
            pubkeys.append(pub_i)
        with open('test_aggregate_public_keys', 'w') as f:
                for k in pubkeys:
                    f.write(k.hex() + '\n')
        public_keys_list = m2.read_bytes_from_hex_list('test_aggregate_public_keys')
        combined_key = None
        for k in pubkeys:
            ck, coeff_i = m2.aggregate_public_keys(public_keys_list, k)
            if combined_key is None:
                combined_key = ck
            else:
                assert combined_key == ck
            coeffs.append(coeff_i)
        assert not m2.is_infinite(combined_key)
        combined_sec = 0
        for sec, coeff in zip(secrets, coeffs):
            if m2.has_even_y(combined_key):
                sec = m2.n - sec
            combined_sec += sec * coeff
            combined_sec %= m2.n
        pubkey_check = m2.point_mul(m2.G, combined_sec)
        assert m2.bytes_from_point(pubkey_check) == m2.bytes_from_point(combined_key)
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
            nonce = b''
            for ind in range(m2.nu):
                r_1j = m2.seckey_gen()
                R_1j = m2.pubkey_gen(r_1j, compressed = True)
                R_1j_check = m2.point_mul(m2.G, m2.int_from_bytes(r_1j))
                assert R_1j_check == m2.lift_x(R_1j)
                nonce_secrets.append(r_1j)
                nonce += R_1j
                aggregated_nonces[ind] = m2.point_add(aggregated_nonces[ind], R_1j_check)
            nonces.append(nonce)
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
            nonce = b''
            for _ in range(m2.nu):
                r_1j = m2.seckey_gen()
                R_1j = m2.pubkey_gen(r_1j, compressed = True)
                nonce_secrets.append(r_1j)
                nonce += R_1j
            nonces.append(nonce)
        aggregate_nonce_points = m2.aggregate_nonces(nonces)
        aggregated_nonce_bytes = [m2.bytes_from_point(R, compressed = True) for R in aggregate_nonce_points]
        b = m2.hash_nonces(random_pubkey, aggregated_nonce_bytes, b'hello world')
        R = m2.compute_R(aggregate_nonce_points, b)

        secret_check = 0
        for p in range(5):
            for n in range(m2.nu):
                nonce_secret = m2.int_from_bytes(nonce_secrets[m2.nu*p + n])
                if not m2.has_even_y(R):
                    nonce_secret = m2.n - nonce_secret
                secret_check += nonce_secret * (b**n)
                secret_check %= m2.n

        R_check = m2.point_mul(m2.G, secret_check)
        assert m2.bytes_from_point(R) == m2.bytes_from_point(R_check)

        sys.stdout.write('.')
        sys.stdout.flush()
    sys.stdout.write('\rtest_compute_R PASSED\n')
    sys.stdout.flush()

def test_compute_s():
    for _ in range(10):
        random_privkey = m2.seckey_gen()
        random_pubkey = m2.pubkey_gen(random_privkey)
        random_chall = random.randint(1, m2.n - 1)
        random_a_1 = random.randint(1, m2.n - 1)
        random_b = random.randint(1, m2.n - 1)
        our_R = None
        nonce_secrets = []
        for j in range(m2.nu):
            r_1j = m2.seckey_gen()
            nonce_secrets.append(r_1j)
            R_1j = m2.pubkey_gen(r_1j)
            bj_R_1j = m2.point_mul(m2.lift_x(R_1j), (random_b**j)%m2.n)
            our_R = m2.point_add(our_R, bj_R_1j)
        s = m2.compute_s(random_chall, random_privkey, random_a_1, nonce_secrets, random_b)
        S = m2.point_mul(m2.G, s)
        a_1_pubkey = m2.point_mul(m2.lift_x(random_pubkey), random_a_1)
        c_a_1_pubkey = m2.point_mul(a_1_pubkey, random_chall)
        S_check = m2.point_add(c_a_1_pubkey, our_R)
        assert S == S_check

        sys.stdout.write('.')
        sys.stdout.flush()
    sys.stdout.write('\rtest_compute_s PASSED\n')
    sys.stdout.flush()


if __name__ == "__main__":
    test_seckey_gen()
    test_read_write_bytes()
    test_point_serialisation()
    test_aggregate_public_keys()
    test_aggregate_nonces()
    test_compute_R()
    test_compute_s()
