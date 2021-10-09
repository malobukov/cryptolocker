# cryptolocker

Encrypts or decrypts a given file or files in place. 

## Usage

    cryptolocker file1 [file2] [...]

More than one file can be specified. Returns 0 on success. Running the same command on encrypted file decrypts it.

Password can be passed via environment variable CRYPTOLOCKER_PASSWORD, or entered at the prompt.

16 bytes are appended at the end of encrypted files that contain CRC32C of plaintext (twice) followed by 64 bit nonce. A suffix ".encrypted" is added to file name. Nonce is generated by XORing file length with the output of hardware random number generator.

Previous versions used file length as nonce, and added a suffix ".encrypted-12345678" to file name, where 12345678 is checksum. Checksum was created by encrypting CRC32C of plaintext, CRC32C of ciphertext, and file length on the same key and with the same algorithm, then taking first 32 bits of the result. For backwards compatibility, this logic is still suppored, but only for decryption.

## Building

Run

    make
    
to create cryptolocker binaries. There are no external dependencies. To cross-compile Windows executable on Linux, install MinGW-w64.

## Limitations

No password stretching or KDF, encryption key is just zero-padded password, so use a long password. Key length is 256 bit, so if the password is more than 32 bytes long then only the first 32 bytes are used.

## Controvercy

Speck cipher was developed by NSA and its release coincided with Snowden revelations. Because of that it is viewed with suspicion by at least some in the cryptographic community. Unlike Dual_EC_DRBG, Speck construction is very simple so there does not seem to be any place for the backdoor, but if that's still a concern for you and NSA is in your threat model, use something else.

Best practice is to use a cryptographic library instead of rolling your own crypto, but that would bring in a large external dependency.

## Site-Specific Password Generation

The companion program password4 creates password for a given site by encrypting FNV-1a hash of site identifier with Speck128/256 on the key passed via environmental variable CRYPTOLOCKER_PASSWORD. Example usage:

    password4 john.doe@example.com

FNV-1a is not cryptographically strong but it does not have to be because potential attacker cannot choose the input. We just want to use all of the input and spread it across 128 bits to avoid collisions (same output for different site identifiers).

Passwords are trimmed to 16 base-58 characters separated by dashes in 4 group of 4, for a total of 19 characters. This should fulfill password length and complexity requirements of most web sites (uppercase, lowercase, special character, etc.)

Alternatively this can be done in a browser like Firefox that supports BigInt by opening [https://malobukov.github.io/cryptolocker/password4.html](https://malobukov.github.io/cryptolocker/password4.html).

## References

Speck implementation guide https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
