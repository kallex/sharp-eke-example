sharp-eke-example
=================

Encrypted Key Exchange (EKE) example on C#

Example of EKE-implementation on C# using RSA (1024) bit and AES (128 bit)
- The key to encrypt the public key pair is possibly not secure, SHA256 without salting from the plaintext passwd


This example is quite simply and not particularly sample-polished, but there isn't much clutter either.

Console app can be debugged through to follow up the EKE-phases.

The actual implementation is going to "The Ball" trust-model, but I wanted to share this
separate part as I couldn't find any EKE implementation on C# for the time being.


Cheers,

Kalle