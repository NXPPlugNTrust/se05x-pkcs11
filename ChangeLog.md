# Changelog


## [4.6]

- Extended digest operation to input data > 1024.

- HMAC (sign and verify) operation support.

- Bug fix: List object for uses cases where secure element has more than appr. 200 objects.

- RSA Encrypt / decrypt operation support.

- RSA Sign and verify multi-step operations supported.

- ECDSA multi-step operation support.

- Test scripts updated with counterpart testing.

- Fixes for memory leaks and static analysis findings.


## [4.4] First version of GitHub release

- Features supported - EC crypto (EC key generation, EC sign/verify, ECDH compute key), RSA crypto (RSA key generation, RSA sign/verify), Random generator, Object import/delete/export (public part), Message digest, Symmetric key generation

- Key label handling - The endianness of the key id passed in the key label (--label) is not changed.


## [x.x] Previous versions of PKCS11 are released from Plug and Trust Standard package at https://www.nxp.com/products/:SE051.
