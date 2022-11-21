# Libsodium Example

This app is showing how to use Libsodium's **CryptoBox**.

##What is a CryptoBox ?

The CryptoBox is a **hybrid encryption scheme* that is useful in 1:1 encryptions like a chat app. A 
Hybrid Encryption Scheme is a combination of 2 encryption schemes:

*Part 1: Generation of an encryption key with a key exchange scheme

CryptoBox uses a key exchange system named **Key exchange: X25519** that works equal to Diffie-Hellmann  
scheme - each party uses his own Private Key and the other parties Public Key to generate an 
encryption key. The magic is: both encryption keys are equal. The benefit of this workflow is easy: 
The encryption key itself was never exchanged and cannot get captured by any sniffing operation on a  
a network channel.

*Part 2: Encryption of the plaintext with a symmetric encryption scheme

The CryptoBox uses the encryption key from part 1 that encrypts the plaintext with an additional **nonce**. 
Per definition a nonce means "number used once" and the benefit for this is easy: even we encrypt the same 
plaintext 2 or more time the encrypted result will be completely different.

In Libsodium the encryption is done with **Encryption: XSalsa20** and **Authentication: Poly1305**, 
that is an encryption like "AES GCM" with an authentication tag that prevents any unwanted change of the ciphertext.

*Part 3: Decryption of the ciphertext

The receipient uses his own Private Key and the sender's Public Key to decrypt the message.

**How does the encryption work ?**

*Key generation

In a chat we do have 2 parties, let me name them as A (like Alice) and B (like Bob). Each of them 
generate an own **Keypair** that consist of a **Private Key** (sometimes named as **Secret Key**) 
and a **Public Key**.

Each party stores the Private Key securely and sends the Public Key to the other party. For the 
following workflow lets assume that party B is the sender and party A is the receipient of a message. 

*Encryption

Party B now uses his own Private Key "B" and the receipients Public Key "A" to encrypt the super 
secret message to a **ciphertext** that looks like 

```plaintext
wNZkkY96IDS8wgTiOb+ymFpmrWYp1M3m:5DQZ/oXN8CLXzdtRNLlGdl36vUTZTcIPspqMcEky6FHqgmIGfbTTEhxomZhN8xsrJygqelmuqr0/Lb4=
```

This string consist of 2 parts - the first part is a random number called "nonce" and the second part 
is the ciphertext.

*Decryption

The receipient gets this string combination and already has 2 keys - his own Private Key "A" and the 
sender's Public Key "B". Both keys are used to decrypt the ciphertext string to the decrypted text that 
equals the origianl plaintext. 

The **general Libsodium documentation** is here: https://libsodium.gitbook.io/doc/

*Get the sources for Lazysodium and TweetNacl here:

Lazysodium-Android: https://github.com/terl/lazysodium-android

TweetNacl-Java: https://github.com/InstantWebP2P/tweetnacl-java
