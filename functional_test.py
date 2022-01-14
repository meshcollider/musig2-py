import os
import shutil
import subprocess

import musig2

children = ['one', 'two', 'three']

sig = ''
X = b''

def create_dirs():
    if os.path.exists('musig2-test'):
        shutil.rmtree('musig2-test')
    os.mkdir('musig2-test')
    for child in children:
        os.mkdir(f"musig2-test/{child}")
        musig2.write_bytes("hello world\n".encode(), f"musig2-test/{child}/message")

def gen_pub_keys():
    keys = b''
    for child in children:
        one = subprocess.Popen(["python3", "../../musig2.py", "keygen"],
                        cwd=f"musig2-test/{child}",
                        stdout=subprocess.PIPE
                    )
        stdout, _ = one.communicate()
        pubkey = stdout.split(b' ')[-1]
        keys += pubkey
    for child in children:
        musig2.write_bytes(keys, f"musig2-test/{child}/public_keys")

def gen_nonces():
    nonces = b''
    for child in children:
        one = subprocess.Popen(["python3", "../../musig2.py", "noncegen"],
                        cwd=f"musig2-test/{child}",
                        stdout=subprocess.PIPE
                    )
        stdout, _ = one.communicate()
        stdout = stdout.split(b'\n')
        nonces += b'\n'.join(stdout[3:])
    for child in children:
        musig2.write_bytes(nonces, f"musig2-test/{child}/public_nonces")

def do_sign():
    s_values = b''
    for child in children:
        one = subprocess.Popen(["python3", "../../musig2.py", "sign"],
                        cwd=f"musig2-test/{child}",
                        stdout=subprocess.PIPE
                    )
        stdout, _ = one.communicate()
        stdout = stdout.strip().split(b'\n')
        s_value = stdout[-1].split(b' ')[-1]
        global X
        X = stdout[-3].split(b' ')[-1].decode()
        s_values += s_value + b'\n'
    for child in children:
        musig2.write_bytes(s_values, f"musig2-test/{child}/s_values")

def aggregate_signatures():
    one = subprocess.Popen(["python3", "../../musig2.py", "aggregatesignature"],
                    cwd=f"musig2-test/one",
                    stdout=subprocess.PIPE
                )
    stdout, _ = one.communicate()
    global sig
    sig = stdout.strip().split(b'\n')[-1].split(b' ')[-1].decode()

def do_verify():
    print(f"X: {X}")
    #print(f"R: {R}")
    print(f"S: {sig}")
    one = subprocess.Popen(["python3", "../../musig2.py", "verify", X, sig],
                    cwd=f"musig2-test/one",
                    stdout=subprocess.PIPE
                )
    stdout, _ = one.communicate()
    print(stdout.decode())

def main():

    create_dirs()
    gen_pub_keys()
    gen_nonces()
    do_sign()
    aggregate_signatures()
    do_verify()





if __name__ == "__main__":
    main()
