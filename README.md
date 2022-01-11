# musig2-py
Experimental musig2 python code, not for production use! This is just for testing things out.

All public keys are encoded as 32 bytes, assuming a positive y coordinate, as in BIP-340.

## Usage

1. First generate a public and private keypair:

```
> python3 musig2.py keygen
Your public key: f5c9424f7f553380f8aa6a4081c73443d51d914350649d0a9386f19a2d1dfbe0
```

This will create a file `secret.key` containing the secret key for the above public key. Keep this safe.

2. Generate nonces:

```
> python3 musig2.py noncegen
Your nonces:
e0a8d714013c81ad3c70941d6521a9745d7a2be579fe6eb59409cdd3caeb10ab
4493266d431838d54e667dd2337b744a5dc79bb9ece40b6a89c85a0bce2347f1
```

This will also create a file `secret_nonces` containing the secrets corresponding to these nonces.

3. Send your public key and two nonces to all other participants in the multisig.

4. Receive from all participants their public keys and create a file called `public_keys` containing all these keys (including your own). The order is not important. For example:

```
f5c9424f7f553380f8aa6a4081c73443d51d914350649d0a9386f19a2d1dfbe0
ba843eb2f7540fb38e44937b1cbd2a4c6d3ed7f8d637af9c9066f3ebaec50e7e
90bec63c45bf27a6447d8f1395166a672353c2289d7484b42826527314da3bf9
```

6. Generate the aggregate public key:

```
> python3 musig2.py aggregatekeys
Aggregating 3 public keys...
Aggregate public key: 081845cea7b4fbdf02196e3cda12a33c46c78d9107f9a1902e96f1dd6fa35721
```

This public key does not depend on the nonces for this session, and will remain the same even if all participants delete their `secret_nonces` files and generate new nonces. This will be the final public key used for verification of the signature.

5. Receive from all participants their nonces for this signing session, and create a file called `public_nonces` containing all these nonce pairs. The two nonces from each participant must be kept in order, but the order of the participants is not important. For example:

```
e0a8d714013c81ad3c70941d6521a9745d7a2be579fe6eb59409cdd3caeb10ab
4493266d431838d54e667dd2337b744a5dc79bb9ece40b6a89c85a0bce2347f1
895a624dd471c190473bbd68f10a01e72740da503a7a4d03e880504b73298bf5
6708ff5d15cc370c4c06e1f4dff9f0441d3a05b7274d11a41d158127ddf6bf23
0c62430479df030971d5231df8bf13cb0a724fdf955aa682afd89d71c6fc8235
e5d30f81aebfe03c476be55192d9b59d6c8888c2cd1ae8bd06ece0d1434e3aba
```

6. Create a file called `message` containing the message you wish to sign. The contents of the file are interpreted as bytes, not as a string. Then use the `sign` command to generate a partial signature.

```
> cat message
hello world
> python3 musig2.py sign
Aggregating 3 public keys...
Aggregate public key: 081845cea7b4fbdf02196e3cda12a33c46c78d9107f9a1902e96f1dd6fa35721
Signature R: 543ed1228dc2b2b97a8505c5c4bbc7af804337ba63764dedb3253d841650908a
Partial signature s_1: 25790076415926875293701632275920825069309645224975202011864494087233169488661
```

7. Send the partial signature `s_1` to all other parties and receive their partial signatures. Create a file called `s_values` containing all these partial signatures (order does not matter):

```
70422816632651700204487150071800525577195829262243917568538125546269304740490
52745170049204061921510945259991613865907364545401375100071360259398594491612
25790076415926875293701632275920825069309645224975202011864494087233169488661
```

8. Aggregate the partial signatures:

```
> python3 musig2.py aggregatesignature
Aggregating 3 public keys...
Aggregate public key: 081845cea7b4fbdf02196e3cda12a33c46c78d9107f9a1902e96f1dd6fa35721
Hex-encoded signature: 543ed1228dc2b2b97a8505c5c4bbc7af804337ba63764dedb3253d841650908a495346a65e2861d2de45a21ccc32c6fd55ecb5279042d998dce6bf3e3cae893a
```

9. Verify the signature created:

```
> python3 musig2.py verify 081845cea7b4fbdf02196e3cda12a33c46c78d9107f9a1902e96f1dd6fa35721 543ed1228dc2b2b97a8505c5c4bbc7af804337ba63764dedb3253d841650908a495346a65e2861d2de45a21ccc32c6fd55ecb5279042d998dce6bf3e3cae893a
Signature is valid: True
```

The format for the verification command is
`verify <public key> <signature>`
