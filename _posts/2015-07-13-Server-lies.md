---
title:      PoliCTF 2015 - Even the server lies (on a couch unfortunately)
author:     cloudstrife
date:       2015-07-13 07:56:00
summary:    Hiding control flow using C++ exceptions
categories: PoliCTF2015 Crypto
tags:
 - PoliCTF
 - Crypto
---

> What do we have here? It seems a normal session between a user and some google servers, but actually one of them is lazy and it's lying on a couch. What a bad luck! Will you be able to exploit this unforgivable behaviour?





The title is a hint: the server tells the client that the communication is encrypted with a certain ciphersuite, while actually the message number 13 has been tampered.

Since message 13 has been tampered with: in the field "encrypted data", the original

```
00000000000000011C27634713D81517AB02A5F51F28E8868BA
89F9764E9FB4078B25689011EE6FC41DD5D5321F99A45A73139
```
has been replaced with

```
93a3c4b2c570e768f4044e0a4c5aeab7b1e2e26ac8371117
```

Padded with as many 00 as needed to match the original length.

Discarding the final 00 and converting `93a3c4b2c570e768f4044e0a4c5aeab7b1e2e26ac8371117` to an integer value we get
`n = 3620115404019777021855203292005859579843541360704566530327i` which can easily be factorized in
`p = 49727547581930298376698201253, q = 72798993315633226794104718859`.


n can be used as a 192 bits rsa modulus in a school textbook rsa implementation.
Message 14 has been altered with the same procedure by injecting the value
`925a684f87209401f4213cf1a6eca21c62d12703d61416bd` which is the ciphertext encrypted
with the public key `<e,n> = <65537, n>`

By factoring n and guessing e (really easy, since 65537 is by far the most common
choice for the encryption exponent),
one is able to compute z = phi(n) and thus the decryption exponent d.
After the decryption the plaintext ```flag{fuuckk-rsa-use-ecc}``` is recovered.

Summing everything up:

```
Original ptx: "flag{fuuckk-rsa-use-ecc}"
Ptx length: 192
Decimal: p = 49727547581930298376698201253, q = 72798993315633226794104718859
Hex: p = a0ada9cc09068b740b0c04a5, q = eb39ea7760dc65daad8b060b
Decimal: n = 3620115404019777021855203292005859579843541360704566530327, and it's 192 bits long
Hex: n = 93a3c4b2c570e768f4044e0a4c5aeab7b1e2e26ac8371117, and it's 192 bits long
Decimal: e = 65537
Hex: e = 10001
BEGIN ENCRYPTION
ptx: 2511413510841792985603231251528729753957701240341594858365
Hex ptx: 666c61677b667575636b6b2d7273612d7573652d6563637d
Decimal ctx: 3588568898129748916244664946454451586293630107020164339389
Hex ctx: 925a684f87209401f4213cf1a6eca21c62d12703d61416bd
END ENCRYPTION
BEGIN DECRYPTION
Decimal: z = 3620115404019777021855203291883333038945977835533763610216
Hex: z = 93a3c4b2c570e768f4044e08c073567447fff11c0fa00668
Decimal: d = 2393782461031189358974580616400752560778840891110230553921
Hex: d = 61a041491555fb2f636c154da434a04e73edc23993fb7541
Decimal ctx: 3588568898129748916244664946454451586293630107020164339389
Hex ctx: 925a684f87209401f4213cf1a6eca21c62d12703d61416bd
ptx: 2511413510841792985603231251528729753957701240341594858365
Hex ptx: 666c61677b667575636b6b2d7273612d7573652d6563637d
END DECRYPTION
All ok? true
Decrypted message: "flag{fuuckk-rsa-use-ecc}" 
```

