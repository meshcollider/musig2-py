# musig2-py
Experimental musig2 python code, not for production use! This is just for testing things out.

All public keys are encoded as 32 bytes, assuming a positive y coordinate, as in BIP-340.

## Usage

1. First generate a public and private keypair:

```
> python3 musig2.py keygen
Your public key: 7b218d25a6bd910c5ef56fb383f64f1a9d739b6dbbfd9047a55b0dcb07e81f77
```

This will create a file `secret.key` containing the secret key for the above public key. Keep this safe.

2. Generate nonces:

```
> python3 musig2.py noncegen
Your nonces:
67bf76acb6e81f5aa14636d40e106a057a577544e0718894b1529d001a70e583
ec82fd28ee5ece35242c7c87cc0e2ab7859989c373e57d4298b5ac0c519f4b26
```

This will also create a file `secret_nonces` containing the secrets corresponding to these nonces.

3. Send your public key and two nonces to all other participants in the multisig.

4. Receive from all participants their public keys and create a file called `public_keys` containing all these keys (including your own). The order is not important. For example:

```
7b218d25a6bd910c5ef56fb383f64f1a9d739b6dbbfd9047a55b0dcb07e81f77
e5cf328d2e2e46ad7fe2f354e8be6725e04ee067f66253581d496c4e5cc3a281
4661bc027ad61d10e71fee19ddc62d14fdeebcf4b816a5bf267db76e8451dd72
```

6. Generate the aggregate public key:

```
> python3 musig2.py aggregatekeys
Aggregating 3 public keys...
Aggregate key has odd y, repeating with negated coefficients
Aggregate public key: 6f62ba28b5100f756443156ec9389a77c16e35d6f18a2257cad0c515c8167bb9
```

This public key does not depend on the nonces for this session, and will remain the same even if all participants delete their `secret_nonces` files and generate new nonces. This will be the final public key used for verification of the signature.

5. Receive from all participants their nonces for this signing session, and create a file called `public_nonces` containing all these nonce pairs. The two nonces from each participant must be kept in order, but the order of the participants is not important. For example:

```
67bf76acb6e81f5aa14636d40e106a057a577544e0718894b1529d001a70e583
ec82fd28ee5ece35242c7c87cc0e2ab7859989c373e57d4298b5ac0c519f4b26
53473efb5b7f1dfe163443c6441b83c8e7c2f44cff7f4bf5c97ce3e1452cee35
b9f2455cea633b72f87550dd2597a58ce3b056fe62ef2506b0da2e840c715dab
3ab97a73cca7529855cefb1ef6582c1f0f301ad085c8e131a15fe5f498aab0d5
15b276a5c095426adf270fd03341d0550c4a8c683b5f3a842c41948ad624479b
```

6. Create a file called `message` containing the message you wish to sign. The contents of the file are interpreted as bytes, not as a string. Then use the `sign` command to generate a partial signature.

```
> cat message
hello world
> python3 musig2.py sign
Aggregating 3 public keys...
Aggregate key has odd y, repeating with negated coefficients
Aggregate public key: 6f62ba28b5100f756443156ec9389a77c16e35d6f18a2257cad0c515c8167bb9
Signature R: b9315da361154b7b6aafcbfb78769f33e6b845f55b3ab9e9b9195e6efd5ec6c1
Partial signature s_1: 50c7fe9e8f3430b60f57c28664f97bf2d246a24a913de79336697721743ccb04
```

7. Send the partial signature `s_1` to all other parties and receive their partial signatures. Create a file called `s_values` containing all these partial signatures (order does not matter):

```
50c7fe9e8f3430b60f57c28664f97bf2d246a24a913de79336697721743ccb04
38ba61d221cf9d3fb36f8a1505681cc63a6714bc506c361404c5637ee87fd4ad
89543057dde76bae8bedc2183cd92fe50ac37c05e045763d12b3e6986573e581
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
