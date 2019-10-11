// cryptolocker.cpp
//
// Encrypts or decrypts given file(s) or all files in a given folder, recursively
//
// Prerequisites:
//
//   sudo apt-get install gcc-8 g++-8
//
// Applies Speck128/256 in CTR mode, as a stream cipher, using file length as nonce.
// This can potentially be a problem, as encrypting two files of the same size with 
// the same key leaks their XOR, but should be ok for the intended use: occasionally 
// encrypting large archive files.
//
// Not having to carry the nonce allows encryption in place, without changing file length. 
//
// Byte order and test vectors as in Speck implementation guide 
// https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
//
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream> 
#include <iostream>

static inline void
speck_round(uint64_t& x, uint64_t& y, const uint64_t k)
{
  x = (x >> 8) | (x << (8 * sizeof(x) - 8)); // x = ROTR(x, 8)
  x += y;
  x ^= k;
  y = (y << 3) | (y >> (8 * sizeof(y) - 3)); // y = ROTL(y, 3)
  y ^= x;
}

static void 
speck_encrypt( const uint64_t plaintext[2]
             , const uint64_t key[4]
             , uint64_t ciphertext[2]
             )
{
  uint64_t a = key[0];
  uint64_t bcd[3] = {key[1], key[2], key[3]};
  ciphertext[0] = plaintext[0];
  ciphertext[1] = plaintext[1];
  for (unsigned i = 0; i < 34; i++) {
    speck_round(ciphertext[1], ciphertext[0], a); 
    speck_round(bcd[i % 3], a, i);
  }
}

static uint64_t 
bytes_to_uint64(const uint8_t bytes[], unsigned length)
{
  uint64_t w = 0;
  for (unsigned i = 0, shift = 0; i < length; i++, shift += 8) {
    w |= ((uint64_t)bytes[i] << shift);
  }
  return w;
}

static int // Return 0 on success
process_one_file(std::filesystem::path path, std::uintmax_t length, const uint64_t key[4])
{
  std::cerr << "Processing " << path << "\n";
  std::fstream f(path, std::fstream::in | std::fstream::out | std::fstream::binary);
  if (!f.is_open()) {
    std::cerr << "Cannot open " << path << "\n";
    return 1;
  }

  // Make progress bar length proportional to log of file size, plus intercept
  unsigned total_notches = 10;
  auto remaining_length = length;
  while (remaining_length >>= 1) total_notches++;
  remaining_length = length;
  std::cerr << " ";
  for (unsigned i = 0; i < total_notches; i++) {
    std::cerr << "▒"; // U+2592 Medium shade
  }
  std::cerr << " \r ";
  unsigned notches_shown = 0;

  uint64_t nonce_and_counter[2] = { length, 0 };
  uint64_t keystream[2];

  char buffer[16];
  while (remaining_length) {

  	// Advance the keystream
  	speck_encrypt(nonce_and_counter, key, keystream);
  	nonce_and_counter[1]++;

    // Remember current position, read next chunk, move file pointer back
    auto position = f.tellg();
  	std::uintmax_t chunk_size = remaining_length < 16 ? remaining_length : 16;
    f.read(&buffer[0], chunk_size);
    if (!f.good()) {
      std::cerr << "Error reading " << path << "\n";
      return 1;
    }
    f.seekg(position);

    // XOR buffer with keystream
    // Same byte order as in Words64ToBytes() from implementation guide
    for (unsigned i = 0; i < 8; i++) {
      buffer[i] ^= keystream[0] >> (i * 8);
      buffer[i + 8] ^= keystream[1] >> (i * 8);
    }

    // Write processed buffer back
    f.write(&buffer[0], chunk_size);
    if (!f.good()) {
      std::cerr << "Error writing " << path << "\n";
      return 1;
    }

    remaining_length -= chunk_size;

    // Update progress bar if needed 
    auto notches_remaining = total_notches - (unsigned)(((double)length - remaining_length) * total_notches / length);
    if (total_notches - notches_shown > notches_remaining) {
      auto notches_to_show = total_notches - notches_shown - notches_remaining;
      while (notches_to_show--) {
        std::cerr << "█"; // U+2588 Full block
        notches_shown++;
      }
    }
  }
  f.close();
  std::cerr << "\r ";
  for (unsigned i = 0; i < total_notches; i++) {
    std::cerr << ' ';
  }
  std::cerr << " \r";
  return 0;
}

int main(int argc, char** argv)
{
  int start_with = 1; // filenames start from argv[1]
  char* password = std::getenv("CRYPTOLOCKER_PASSWORD");
  if (!password) {
    start_with = 2; // filenames start from argv[2]
  }

  // When called without filename(s), run self-test using published test vectors and show usage
  if (argc <= start_with) {
  	const uint64_t key[4]       = { 0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL
                                  , 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL };
    const uint64_t plaintext[2] = { 0x202e72656e6f6f70ULL, 0x65736f6874206e49ULL };
    const uint64_t expected[2]  = { 0x4eeeb48d9c188f43ULL, 0x4109010405c0f53eULL };
    uint64_t observed[2];
    speck_encrypt(plaintext, key, observed);
    if ( expected[0] != observed[0] 
      || expected[1] != observed[1]
       ) {
      std::cerr << "speck_encrypt() self-test failed\n" 
                << "Expected 0x" << std::hex << expected[0] << ", 0x" << expected[1] << "\n"
                << "Observed 0x" << observed[0] << ", 0x" << observed[1] << "\n";
       return 1;
    }
    const uint64_t converted[2] =  { bytes_to_uint64((uint8_t*)"pooner. ", 8)
                                   , bytes_to_uint64((uint8_t*)"In those", 8)};
    if ( plaintext[0] != converted[0] 
      || plaintext[1] != converted[1]
       ) {
      std::cerr << "bytes_to_uint64() self-test failed\n" 
                << "Expected 0x" << std::hex << plaintext[0] << ", 0x" << plaintext[1] << "\n"
                << "Observed 0x" << converted[0] << ", 0x" << converted[1] << "\n";
       return 1;
    }
  	std::cerr << "Usage:\n\n\tcryptolocker password file\n\n"
  	  "Encrypt or decrypt given file or all files in a given directory recursively with Speck128/256 in counter mode. "
      "Password can also be passed via environment variable CRYPTOLOCKER_PASSWORD, in which case all command-line "
      "arguments are interpreted as file or folder names.\n";
  	return 0;
  }

  if (start_with == 2) {
    password = argv[1];
  }

  // Convert password to four little-endian 64-bit words, zero padded,
  // as in BytesToWords64() from implementation guide 
  uint64_t k[4] = {0};
  unsigned bytes_left = strlen(password);
  if (bytes_left < 16) {
    std::cerr << "WARNING: password is less than 16 characters long\n";
  } else if (bytes_left > 32) {
    std::cerr << "WARNING: password is longer than 32 characters, only using the first 32\n";
  }
  for (unsigned i = 0; i < 4; i++, bytes_left -= 8) {
    k[i] = bytes_to_uint64((uint8_t*)(password + i * 8), bytes_left > 8 ? 8 : bytes_left);
    if (bytes_left <= 8) break;
  }

  // Replace password with stars so that it does not appear in process list
  if (start_with == 2) {
    while (*password) *password++ = '*'; 
  }

  // Iterate over the given files or folders (can be more than one)
  for (int i = start_with; i < argc; i++) {
    auto p = std::filesystem::path(argv[i]);
  	auto s = std::filesystem::status(p);
    if (std::filesystem::is_regular_file(s)) {
      if (process_one_file(p, std::filesystem::file_size(p), k)) return 1;
    } else if (std::filesystem::is_directory(s)) {
      for (auto& q: std::filesystem::recursive_directory_iterator(argv[i])) {
      	if (q.is_regular_file()) {
          if (process_one_file(q.path(), q.file_size(), k)) return 1;
        }
      }
    }
  }
  return 0;
}
