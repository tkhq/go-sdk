# Enclave One Shot Encryption

This package hosts a set of primitives for sending and encrypting message from a user to an enclave or vice versa.

N.B. Neither the client or the server should ever be reused to send/receive more then one message. We want to avoid the recipient target key being used more then once in order to improve forward secrecy; see [security profile](#security-profile) section for more details.

## Terms

- Encapsulated ("Encapped") Key - the public key of the sender used for ECDH.
- Target Key Pair - the key pair of the receiver that the sender encrypts to the public key of. Only one message should ever be encrypted to the public key.
- Server - a server inside of the enclave; normally an enclave application.
- Client - a client outside of the enclave; normally a turnkey end user.
- Enclave Auth Key Pair - a key pair derived from the quorum master seed specifically for the purpose of authentication with clients.

## Overview

This protocol builds on top of the HPKE standard ([RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180)) by adding recipient pre-flight authentication so the client can verify it is sending ciphertext to a turnkey controlled enclave and the enclave can verify its sending ciphertext to the correct client. See the [security profile](#security-profile) section more details.

## HPKE Configuration

KEM: KEM_P256_HKDF_SHA256
KDF: KDF_HKDF_SHA256
AEAD: AEAD_AES256GCM
INFO: b"turnkey_hpke"
ADDITIONAL ASSOCIATED DATA: EncappedPublicKey||ReceiverPublicKey

## Protocol

### Server to Client

1. Client generates target pair and sends clientTargetPub key to server. The authenticity of the clientTargetPub is assumed to have been verified by the Ump policy engine.
1. Server computes ciphertext, serverEncappedPub = ENCRYPT(plaintext, clientTargetPub) and clears clientTargetPub from memory.
1. Server computes serverEncappedPub_sig_enclaveAuthPriv = SIGN(serverEncappedPub, enclaveAuthPriv).
1. Server sends (ciphertext, serverEncappedPub, serverEncappedPub_sig_enclaveAuthPriv) to client.
1. Client runs VERIFY(serverEncappedPub, serverEncappedPub_sig_enclaveAuthPriv).
1. Client recovers plaintext by computing DECRYPT(ciphertext, serverEncappedPub, clientTargetPriv) and the client target pair is cleared from memory. If the target pair is used multiple times we increase the count of messages that an attacker with the compromised target private key can decrypt.

Note there is no mechanism to prevent a faulty client from resubmitting the same target public key.

### Client to Server

1. Client sends request to server for target key.
1. Server generates server target pair and computes serverTargetPub_sig_enclaveAuthPriv = SIGN(serverTargetPub, enclaveAuthPriv).
1. Server sends (serverTargetPub, serverTargetPub_sig_enclaveAuthPriv) to client.
1. Client runs VERIFY(serverTargetPub, serverTargetPub_sig_enclaveAuthPriv).
1. Client computes ciphertext, clientEncappedPub = ENCRYPT(plaintext, serverTargetPub) and clears serverTargetPub from memory.
1. Client sends (ciphertext, clientEncappedPub) to server and the client is cleared from memory.
1. Server assumes the authenticity of clientEncappedPub has been verified by the Ump policy engine.
1. Server recovers plaintext by computing DECRYPT(ciphertext, clientEncappedPub, clientTargetPriv) and server target pair is cleared from memory. If the target pair is used multiple times we increase the count of messages that an attacker with the compromised target private key can decrypt.

## Security profile

- Receiver pre-flight authentication: we achieve recipient authentication for both the server and client:
  - Client to Server: client verifies that the server's target key is signed by the enclaveAuth key.
  - Server to Client: server relies on upstream checks by Ump + activity signing scheme to enforce rules that guarantee authenticity of the clients target key. Specifically, when the client "sends" clientTargetPub it actually submits a signed payload (activity), and that payload must be signed with an existing credential persisted in org data.
- Forward secrecy: the underlying HPKE spec does not provide forward secrecy on the recipient side since the target key can be long lived. To improve forward secrecy we specify that the a target key should only be used once by the sender and receiver.
- Sender authentication: we use OpMode Base and forgo authentication that the sender possessed a given KEM private key. In order for this to be taken advantage of, an attacker would need to compromise the receivers target private key, intercept the message, decrypt it, and then re-encrypt with different plaintext. In our use case, if the attacker intercepts the receivers target private key, everything is already broken so the extra level of authentication is not necessary. Read more about HPKE asymmetric authentication [here](https://datatracker.ietf.org/doc/html/rfc9180#name-authentication-using-an-asy).
