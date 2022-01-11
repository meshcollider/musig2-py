# musig2-py
Experimental musig2 python code, not for production use! This is just for testing things out.

All public keys are encoded as 32 bytes, assuming a positive y coordinate, as in BIP-340.

## Usage

1. First generate a public and private keypair:

```
> python3 musig2.py keygen
Your public key: 57fe721cd258b506d81ed97942d469c36a27169c82a1fcb2c8134a197209d725
```

This will create a file `secret.key` containing the secret key for the above public key. Keep this safe.

2. Generate nonces:

```
> python3 musig2.py noncegen
Your nonces:
2706f5cce1e48fbea3c63e4a6654a0bc44c71d3cb7f2c6dc10f7b1fead960bc6
1cc402082c5d5bd21bb2087df93e13f4689b6379a32aa013e2e4eea8054fd7be
```

This will also create a file `secret_nonces` containing the secrets corresponding to these nonces.

3. Send your public key and two nonces to all other participants in the multisig.

4. Receive from all participants their public keys and create a file called `public_keys` containing all these keys (including your own). The order is not important. For example:

```
57fe721cd258b506d81ed97942d469c36a27169c82a1fcb2c8134a197209d725
051e6d346d5aed9bbb545eca5911a01b4a86ef2471e289b3dfdc9bc5405671df
b157adf6207fe98b57f1256fc74ea0b105508c391fd097a864c69f65665804fe
```

6. Generate the aggregate public key:

```
> python3 musig2.py aggregatekeys
Aggregating 3 public keys...
Aggregate key has odd y, repeating with negated coefficients
Aggregate public key: 07564a88e2ed1adb7780bbab6a9e6441d63d066a43b99e347fccfdb4b928d128
```

This public key does not depend on the nonces for this session, and will remain the same even if all participants delete their `secret_nonces` files and generate new nonces. This will be the final public key used for verification of the signature.

5. Receive from all participants their nonces for this signing session, and create a file called `public_nonces` containing all these nonce pairs. The two nonces from each participant must be kept in order, but the order of the participants is not important. For example:

```
2706f5cce1e48fbea3c63e4a6654a0bc44c71d3cb7f2c6dc10f7b1fead960bc6
1cc402082c5d5bd21bb2087df93e13f4689b6379a32aa013e2e4eea8054fd7be
57b08e11ae2c7f86b82a99aa79745c12f64f2a5389e347c01424a6a6cdd1285f
44ebf1f17d50e27ae6f2ebe26afd8576b3ac37bf385a38bef8625651557a1857
7aa25e08a61891d4d91556a48268b27bc771a1bb4d65796e106673a9fbbad186
2768d452501b55a021cd3b22c9830afc679d6e61015f1904eedef888f9d5fc88
```

6. Create a file containing the message you wish to sign. The contents of the file are interpreted as bytes, not as a string. By default, this code will use a file called `message` but the file can be specified explicitly:

```
> cat message_file
hello world
> python3 musig2.py sign message_file
Aggregating 3 public keys...
Aggregate key has odd y, repeating with negated coefficients
Aggregate public key: 07564a88e2ed1adb7780bbab6a9e6441d63d066a43b99e347fccfdb4b928d128
Partial signature s_1: 105572589729321001076076397839838647046664845281204947016777578934748384245774
Signature R: 12494b112d60ea032bf5f5092fc7d2f95d32dff09d90ad71aea62f0ceea56835
```

7. Send the partial signature `s_1` to all other parties and receive their partial signatures. Create a file called `s_values` containing all these partial signatures (order does not matter):

```
105572589729321001076076397839838647046664845281204947016777578934748384245774
97378688813626425823134797822572020030973565458797817375930230744176068847551
71655178093065445183346618280366295552770183664865169975041136477165470355206
```

8. Aggregate the partial signatures:

```
> python3 musig2.py aggregatesignature
Signature s: 43022278161380481235415843925401146924733465846718125602538619873053600459857
```

9. Verify the signature created:

```
> python3 musig2.py verify 07564a88e2ed1adb7780bbab6a9e6441d63d066a43b99e347fccfdb4b928d128 12494b112d60ea032bf5f5092fc7d2f95d32dff09d90ad71aea62f0ceea56835 43022278161380481235415843925401146924733465846718125602538619873053600459857 message_file
Signature is valid: True
```

The format for the verification command is
`aggregate_public_key signature_R signature_s [message_filename (optional)]`
