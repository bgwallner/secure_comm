# secure_comm

Purpose
-------

Provide an example of IPC between two process using Botan C++ for handling crypto operations.

Hybrid RSA key-transport with symmetric MAC authentication
----------------------------------------------------------

Example illustrates a setup of communication using a symmetric (private key). The sender initiates the key exchange by creating an RSA 2048 key pair. The sender shares the public key to the receiver through a POSIX message queue. The channel for key-exchange is considered as a secure channel in this example. The receiver now creates a symmetric key by generating a random 128 bit number. Receiver use the public key to encrypt the symmetric key. The receiver then sends it to the sender by adding it to the message queue. The sender uses the private key in the RSA key-pair to decrypt the encrypted received buffer containing the symmetric key. The key is used for periodic communication (assumed non-sensitive data) from sender to receiver to calculate and append CMAC to each message sent. The receiver can use its symmetric key to verify the message integrity by comparing appended CMAC with calculated CMAC.

A short note on the completeness of example
-------------------------------------------

The pre-requisite for the example is that the exchange of the public key is done in a secure communication channel. The POSIX message queues is considered as secure during key-exchange but during periodic communication it is not.

1) Attacker could otherwise use this public key, generate a random number , encrypt with public key, and return to sender.
2) Attacker could otherwise tamper content which would render it useless.

How to use
----------

make clean && make  && ./run.sh