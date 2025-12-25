# secure_comm

Purpose
-------

Provide an example of IPC between two process using Botan C++ for handling crypto operations.

Hybrid RSA key-transport with symmetric MAC authentication
----------------------------------------------------------

Example illustrates a setup of communication using a symmetric (private key). The sender initiates the key exchange by creating an RSA 2048 key pair. The sender shares the public key to the receiver through a POSIX message queue. The receiver now creates a symmetric key by generating a random 128 bit number. Receiver use the public key to encrypt the symmetric key. The reciever then calculates a CMAC of the encrypted buffer and appends it to to the end of the encrypted buffer and then send it to the sender by adding it to the message queue. The sender uses the private key in the RSA key-pair to decrypt the encrypted received buffer (excluding last 16 byte CMAC). When decryption is done the symmetric key "candidate" is used for calculating a CMAC over the received encrypted buffer (excluding last 16 byte CMAC). The calculated CMAC is then compared to the last 16 byte of the received encrypted buffer cotaining the appended CMAC. If these match the sender can conclude that no adversary has been involved tampering the key and thus can trust the key. The key is used for periodic communication (assumed non-sensitive data) from sender to receiver to calculate and append CMAC to each message sent. The receiver can use its symmetric key to verify the message integrity by comparing appended CMAC with calculated CMAC.

A short note on the completeness of example
-------------------------------------------

An attacker having the public key may generate a private key intercepting the key-exchange of symmetric key from receiver to sender. Since data is not sensitive in this case it will only cause receiver to fail with MAC verification.

Another solution would be to pre-share public keys. Sender sharing public key for encryption of symmetric key at receiver. Receiver share public key for verifying signature. Receiver sign message with its private key. Sender verify signature with public key from receiver and decrypt message with its own private key. This is very much how key-exchange is done when sending encrypted emails.

Howver, thinking about this an attacker could as well do the same thing as with the MAC and instead sharing its public key to the sender. Thus, we have moved the problem from one place to another.

But how can we then send encrypted emails using the mechanism above for the key-exchange? In contrast to the POSIX message mail-services also provide lower layer security e.g. TLS which makes communication channel secure.

To otherwise solve this problem pre-sharing of symmetric keys in a secure environment is the most feasonable solution.

How to use
----------

make clean && make  && ./run.sh