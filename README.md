# cryptolocker

Encrypts or decrypts a given file or files. 

## Usage

    cryptolocker [password] file1 [file2] [...]

More than one file can be specified. Returns 0 on success. Running the same command on encrypted file decrypts it.

Password can also be passed via environment variable CRYPTOLOCKER_PASSWORD, in which case all command-line arguments are interpreted as file names.

## Building

There are no external dependencies, just run

    make
    
to create cryptolocker binary.

## Limitations

Applies Speck128/256 in CTR mode, as a stream cipher, using file length as nonce. This can potentially be a problem, as encrypting two files of the same size with the same key leaks their XOR, but should be ok for the intended use: occasionally encrypting large archive files. Not having to carry the nonce allows encryption in place, without changing file length.

When password is specified in the command line, it is replaced with asterisks to prevent it from appearing in process list (although it might still remain in ~/.bash_history or similar command line history files). Beyond that, no attempt is made to purge key material from memory after use. With the tricks modern OS and optimizing compilers play, those are usually futile anyway.

No password stretching or KDF, encryption key is just zero-padded password, so use a long password. Key length is 256 bit, so if the password is more than 32 bytes long then only the first 32 bytes are used.

## Controvercy

Speck cipher was developed by NSA and its release coincided with Snowden revelations. Because of that it is viewed with suspicion by at least some in the cryptographic community. Unlike Dual_EC_DRBG, Speck construction is very simple so there does not seem to be any place for the backdoor, but if that's still a concern for you and NSA is in your threat model, use something else.

Best practice is to use a cryptographic library instead of rolling your own crypto, but that would bring in a large external dependency.

## Site-Specific Password Generation

The companion program password4 creates password for a given site by encrypting FNV-1a hash of site identifier with Speck128/256 on the key passed via environmental variable CRYPTOLOCKER_PASSWORD. Example usage:

    password4 john.doe@example.com

FNV-1a is not cryptographically strong but it does not have to be because potential attacker cannot choose the input. We just want to use all of the input and spread it across 128 bits to avoid collisions (same output for different site identifiers).

Passwords are trimmed to 16 base-58 characters separated by dashes in 4 group of 4, for a total of 19 characters. This should fulfill password length and complexity requirements of most web sites (uppercase, lowercase, special character, etc.)

## References

Byte order and test vectors as in Speck implementation guide https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
