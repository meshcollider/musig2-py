# musig2-py
Experimental musig2 python code, not for production use! This is just for testing things out.

All public keys are encoded as 32 bytes, assuming an even y coordinate, as in BIP-340.

Signatures are 64 bytes. The first 32 bytes encode the x-coordinate of the point R (which is again assumed to have an even y coordinate). The second 32 bytes encode the integer s. This makes them compatible with BIP-340, and hence valid as BIP-341 Taproot Schnorr signatures.

## Usage

1. First generate a public and private keypair:

```
> python3 musig2.py keygen
Your public key:
666e941a926819cb0ea0147a98531cf99e179ca1fc1d8b4dbd6fb9b198fc4f49
```

This will create a file `secret.key` containing the secret key for the above public key. Keep this safe.

2. Send your public key to all other participants involved with this MuSig2 aggregate signing key.

3. Receive from all participants their public keys and create a file called `public_keys` containing all these keys (including your own). The order is not important. For example:

```
666e941a926819cb0ea0147a98531cf99e179ca1fc1d8b4dbd6fb9b198fc4f49
6717de8c80d22400b869981d865ff836af437a41d9a327a6ca2d4d50252b4cd5
dd84fc1a24a05ebef8870614c40fc9045fcc4c0424610c168d335d45b31b2555
```

4. Generate the aggregate public key:

```
> python3 musig2.py aggregatekeys
Aggregate public key:
9875f69e3368d774743d78f80603a05270d4cc72dff90645fadb9a09ec5ebf37
```

This public key will be the final public key used for verification of the signature. It can be used as many times as you (and your co-signers) like. You will need to generate new nonces every time you wish to sign with it, however.

5. Generate a single-use nonce:

```
> python3 musig2.py noncegen
WARNING: Only use this nonce once, then generate a new one.
Reusing nonces to sign different messages will leak your secret key.
Your new nonce:
185cecc34b3991d87c274986df2ad08b5186cc2df1f6928da4fd002cf60b7774123e2f697e06b8d9bbea630e253bfa6f1e0786714772e5c07908ee9de10d9873
```

This will also create a file `secret_nonces` containing the secrets corresponding to this nonce.

6. Send your nonce to all other participants in the multisig, in preparation to sign a message.

7. Receive from all participants their nonces for this signing session, and create a file called `public_nonces` containing all these nonces. The order of the participants is not important. For example:

```
185cecc34b3991d87c274986df2ad08b5186cc2df1f6928da4fd002cf60b7774123e2f697e06b8d9bbea630e253bfa6f1e0786714772e5c07908ee9de10d9873
1faaca07a4a62c5c4efa64b28f37fd353cc74846a6b2bd8ea9c99e59ab861a8f4898c492494bf3447548af391b1f44b345d1b5d2f8d9b740e7e659b26b2caf0b
d413739284b579d0af6474b4ede0b2b38f50bef57c7859d5c32baa9610c0f971711c084e99eb08859c35d0140a9d23441a56cc3db07b9278e6b4ce336f3922b4
```

6. Create a file called `message` containing the message you wish to sign. The contents of the file are interpreted as bytes, not as a string. You can alternatively specify a filename. Then use the `sign <message filename (optional)>` command to generate a partial signature.

```
> cat message
hello world
> python3 musig2.py sign
Aggregate key:
9875f69e3368d774743d78f80603a05270d4cc72dff90645fadb9a09ec5ebf37
Signature R:
90753c99410a4a8b111af67569d6fa56b2b45424d16f2c2950653a0c7c7fcee8
Partial signature s_1:
08348189f0f2cec03bc49b5acafeded13982a9cacc6fab758aa050114a8dc9b5
```

This will delete the secret nonces previous generated to ensure they are not reused. The aggregate key, `R` value, and your partial signature `s_1` will be written to `message.partsig` (or correspondingly for the filename specified) though, in case you forget to copy it from the command line output.

7. Send the partial signature `s_1` to all other parties and receive their partial signatures. Create a file called `s_values` containing all these partial signatures, including your own (order does not matter):

```
08348189f0f2cec03bc49b5acafeded13982a9cacc6fab758aa050114a8dc9b5
3c13ba98da779444d5a247f85fc35c3d02f88185164a462eb16afd9704cc4338
b3e082a44b0ec12b68e58e9d3c4ae980cb76dd1feaa5a2c44d60c08c54b434d5
```

8. Aggregate the partial signatures:

```
> python3 musig2.py aggregatesignature
Hex-encoded signature: 90753c99410a4a8b111af67569d6fa56b2b45424d16f2c2950653a0c7c7fcee8f828bec7167924307a4c71f0670d248f07f2086fcd5f9468896c0e34a40e41c2
```

Again, you can optionally specify the filename of the message being signed if you did not use the default `message`.

9. Verify the signature created:

```
> python3 musig2.py verify 9875f69e3368d774743d78f80603a05270d4cc72dff90645fadb9a09ec5ebf37 90753c99410a4a8b111af67569d6fa56b2b45424d16f2c2950653a0c7c7fcee8f828bec7167924307a4c71f0670d248f07f2086fcd5f9468896c0e34a40e41c2
Signature is valid: True
```

The format for the verification command is
`verify <public key> <signature> <message filename (optional)`

## Testing

This repository includes two types of tests. The unit tests are run on specific functions to ensure individual components are working correctly.
```
> python3 unit_tests.py
test_seckey_gen PASSED
test_read_write_bytes PASSED
test_compute_R PASSED
test_compute_s PASSED
test_aggregate_nonces PASSED
test_aggregate_public_keys PASSED
```

The functional tests run the code externally simulating multiple users in a key establishment and signing session.
```
> python3 functional_test.py
X: ac4a3b78a1368de26f96346cdf87149a2e2d6201b14559120f73c78b1b8253c3
S: 3d18300bbcac308f7f860cc263fe0cafd8a54c0b0a18c953b3f5884dd5012e03bcc45d03cab195223bc6bf98f85f7a4ac33a29eb1d46faac172aec9649cfa678
Signature is valid: True
```
