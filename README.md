# cryptolocker

Encrypts or decrypts a given file or all files in a given folder, recursively. 

## Usage

    cryptolocker password file_or_folder_name

More than one file or folder can be specified. Returns 0 on success. Running the same command on encrypted file decrypts it.

Password can also be passed via environment variable CRYPTOLOCKER_PASSWORD, in which case all command-line arguments are interpreted as file or folder names.

## Building

Written in C++ using some C++17 features, so requires at least GCC 8:

    sudo apt-get install gcc-8 g++-8

There are no external dependencies beyond standard library.

Once you have the compiler, run

    make
    
to create cryptolocker binary.

## Limitations

Applies Speck128/256 in CTR mode, as a stream cipher, using file length as nonce. This can potentially be a problem, as encrypting two files of the same size with the same key leaks their XOR, but should be ok for the intended use: occasionally encrypting large archive files. Not having to carry the nonce allows encryption in place, without changing file length.

No attempt is made to purge key material from memory after use. With the tricks modern OS and optimizing compilers play, those are usually futile anyway.

No password stretching or KDF, encryption key is just zero-padded password. Use a long password. Key length is 256 bit, so if the password is more than 32 bytes long then only the first 32 bytes are used.

Password is passed as a command-line argument so might remain in ~/.bash_history or similar files.

## Controvercy

Speck cipher was developed by NSA and its release coincided with Snowden revelations. Because of that it is viewed with suspicion by at least some in the cryptographic community. Unlike Dual_EC_DRBG, Speck construction is very simple so there does not seem to be any place for the backdoor, but if that's still a concern for you and NSA is in your threat model, use something else.

Best practice is to use a cryptographic library instead of rolling your own crypto, but that would bring in a large external dependency.

## References

Byte order and test vectors as in Speck implementation guide https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
