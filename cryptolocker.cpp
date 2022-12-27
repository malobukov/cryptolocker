// cryptolocker.cpp
//
// Encrypts or decrypts a given file or files
//
// Applies Speck128/256 in CTR mode. A 16 byte long suffix is appended at the end of the file, 
// also encrypted with CTR on the same key, with both nonce and counter set to -1:
//
// Bytes 0-3: CRC32C of plaintext
// Bytes 4-7: CRC32C of plaintext (second copy)
// Bytes 8-15: randomly generated nonce
//
// Older versions used file length as nonce, and kept checksum in filename.
// This can potentially be a problem, as encrypting two files of the same size with the same 
// key leaks their XOR. Decryption code for this approach is kept for backwards compatibility,
// but encryption is now always using random nonces.
//
// Byte order and test vectors as in Speck implementation guide 
// https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
//
// Building:
//
//   g++ -O3 -Wall -Wextra -std=c++17 -march=native -g -o cryptolocker cryptolocker.cpp
//
// To cross-compile Windows executable on Linux, install MinGW-w64:
//
//   sudo apt-get install mingw-w64
//
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctype.h>
#include <fstream> 
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>
#include <x86intrin.h>

static inline void
speck_round(uint64_t& x, uint64_t& y, const uint64_t k)
{
  #if defined(__AVX2__)
    x = __rorq(x, 8);
  #else
    x = (x >> 8) | (x << (64 - 8));
  #endif
  x += y;
  x ^= k;
  #if defined(__AVX2__)
    y = __rolq(y, 3);
  #else
    y = (x << 3) | (y >> (64 - 3));
  #endif
  y ^= x;
}

static void 
speck_schedule( const uint64_t key[4]
              , uint64_t schedule[34]
              )
{
  uint64_t a = key[0];
  uint64_t bcd[3] = {key[1], key[2], key[3]};
  for (unsigned i = 0; i < 33; i++) {
    schedule[i] = a; 
    speck_round(bcd[i % 3], a, i);
  }
  schedule[33] = a; 
}

static void 
speck_encrypt( const uint64_t plaintext[2]
             , const uint64_t schedule[34]
             , uint64_t ciphertext[2]
             )
{
  ciphertext[0] = plaintext[0];
  ciphertext[1] = plaintext[1];
  for (unsigned i = 0; i < 34; i++) {
    speck_round(ciphertext[1], ciphertext[0], schedule[i]); 
  }
}

static void 
speck_encrypt4( const uint64_t plaintext[2 * 4]
              , const uint64_t schedule[34]
              , uint64_t ciphertext[2 * 4]
              )
{
  #if defined(__AVX2__)
    auto x = _mm256_set_epi64x(plaintext[7], plaintext[6], plaintext[5], plaintext[4]);
    auto y = _mm256_set_epi64x(plaintext[3], plaintext[2], plaintext[1], plaintext[0]);
    for (unsigned i = 0; i < 34; i++) {
      auto si = schedule[i];
      x = _mm256_or_si256(_mm256_srli_epi64(x, 8), _mm256_slli_epi64(x, 64 - 8)); // rotate x right by 8
      x = _mm256_add_epi64(x, y);
      x = _mm256_xor_si256(x, _mm256_set_epi64x(si, si, si, si));
      y = _mm256_or_si256(_mm256_slli_epi64(y, 3), _mm256_srli_epi64(y, 64 - 3)); // rotate y left by 3
      y = _mm256_xor_si256(y, x);
    }
    _mm256_storeu_si256((__m256i_u*)&ciphertext[4], x);
    _mm256_storeu_si256((__m256i_u*)&ciphertext[0], y);
  #else
    ciphertext[0] = plaintext[0]; ciphertext[1] = plaintext[1];
    ciphertext[2] = plaintext[2]; ciphertext[3] = plaintext[3];
    ciphertext[4] = plaintext[4]; ciphertext[5] = plaintext[5];
    ciphertext[6] = plaintext[6]; ciphertext[7] = plaintext[7];
    for (unsigned i = 0; i < 34; i++) {
      auto si = schedule[i];
      speck_round(ciphertext[4], ciphertext[0], si); 
      speck_round(ciphertext[5], ciphertext[1], si); 
      speck_round(ciphertext[6], ciphertext[2], si); 
      speck_round(ciphertext[7], ciphertext[3], si); 
    }
  #endif
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
process_one_file(const char* filename, const uint64_t schedule[34], bool restore = false)
{
  std::fstream f(filename, std::fstream::in | std::fstream::out | std::fstream::binary);
  if (!f.is_open()) {
    std::cerr << "Cannot open " << filename << "\n";
    return 2;
  }

  // Determmine file length
  const auto begin = f.tellg();
  f.seekg (0, std::ios::end);
  const auto end = f.tellg();
  f.seekg (0);
  const auto length = (end - begin);
  auto remaining_length = length;

  // If filename ends with ".encrypted", CRC32C (twice) and nonce are appended at the end of the file
  // If filename ends with ".encrypted-XXXXXXXX", where XXXXXXXX are hexadecimal digits, 
  // then XXXXXXXX is checksum, and file length is nonce (for compatibility with previous version)
  bool check_checksum = false;
  uint32_t expected_checksum = 0;
  bool check_crc32c = false;
  uint32_t expected_crc32c = 0;
  bool append_suffix = !restore;
  uint64_t nonce = (uint64_t)length;

  const char* p = filename;
  if (restore) {
    std::cout << "Restoring " << filename << "\n";
  } else {
    std::cout << "Processing " << filename << "\n";
  }
  if (!*p) {
    std::cerr << "Empty filename\n";
    return 1;
  } 
  while (*p) {
    p++; 
  }
  p--; // p points to last character in filename, p - 9 points to '.'
  if (p - 9 > filename) {
    if (strncmp(p - 9, ".encrypted", 10) == 0) {
      if (length >= 16) {
        // Read the suffix
        f.seekg(length - 16);
        uint64_t suffix[2] = {};
        f.read((char*)(&suffix[0]), 16);
        if (!f.good()) {
          std::cerr << "\nError reading suffix from " << filename << "\n";
          return 3;
        }
        f.seekg(0);

        // Decrypt suffix on nonce -1 and counter -1
        const uint64_t all_ones[2]  = { 0xffffffffffffffffULL, 0xffffffffffffffffULL };
        uint64_t gamma[2];
        speck_encrypt(all_ones, schedule, gamma);
        suffix[0] ^= gamma[0];
        suffix[1] ^= gamma[1];

        // See if the two copies of the checksum stored in the suffix match
        const uint32_t crc32c0 = (uint32_t)suffix[0];
        const uint32_t crc32c1 = (uint32_t)(suffix[0] >> 32);
        if (crc32c0 != crc32c1) {
          std::cerr << "CRC mismatch, maybe wrong password?\n";
          return 8;
        }
        check_crc32c = true;
        expected_crc32c = crc32c0;
        nonce = suffix[1];
        remaining_length = length - 16;
        append_suffix = false;
      }
    }
  }
  if (!check_crc32c) { // No suffix in file, but maybe filename contains checksum (from old version)
    while (p > filename && isxdigit(*p)) p--; // p points to '-'
    if (p - 11 > filename) {
      if (strncmp(p - 10, ".encrypted-", 11) == 0) {
        size_t expected_checksum_length = 0;
        expected_checksum = std::stoul(p + 1, &expected_checksum_length, 16);
        if (expected_checksum_length > 0) {
          check_checksum = true;
          append_suffix = false;
        }
      }
    }
  }
  if (append_suffix) { // Use hardware random number generator to create nonce
    long long unsigned int random_number = 0;
    #if defined(__AVX2__)
      if (_rdrand64_step(&random_number) != 1) {
        std::cerr << "_rdrand64_step() failed, will revert to using only file lengh as nonce\n";
      }
    #endif
    nonce ^= (uint64_t)random_number;
  }

  // Make progress bar length proportional to log of file size, plus intercept
  unsigned total_notches = 10;
  {
    auto x = remaining_length;
    while (x >>= 1) total_notches++;
  }
  std::cerr << " ";
  for (unsigned i = 0; i < total_notches; i++) {
    std::cerr << ".";
  }
  std::cerr << " \r ";
  unsigned notches_shown = 0;

  uint64_t nonce_and_counter[2 * 4] = { 
    nonce, nonce, nonce, nonce, 
    0, 1, 2, 3};

  // Use CRC-32C (Castagnoli) for checksum
  uint32_t crc32c_before = ~0U;
  uint32_t crc32c_after = ~0U;
  #if !defined(__AVX2__)
    unsigned crc32c_table[256] = {};
    for (uint32_t i = 0; i < 256; i++) {
      uint32_t j = i;
      for (int k = 0; k < 8; k++) {
        j = j & 1 ? (j >> 1) ^ 0x82f63b78 : j >> 1;
      }
      crc32c_table[i] = j;
    }
  #endif

  while (remaining_length) {

    char buffer[16 * 4 * 1024];
    std::uintmax_t chunk_size = remaining_length;
    if (chunk_size > sizeof(buffer)) {
      chunk_size = sizeof(buffer);
    }

    // Remember current position, read next chunk, move file pointer back
    auto position = f.tellg();
    f.read(&buffer[0], chunk_size);
    if (!f.good()) {
      std::cerr << "\nError reading " << filename << "\n";
      return 3;
    }
    f.seekg(position);

    // Update CRC32C before processing
    for (unsigned offset = 0; offset < chunk_size; offset++) {
      #if defined(__AVX2__)
        crc32c_before = _mm_crc32_u8(crc32c_before, buffer[offset]);
      #else
        crc32c_before = crc32c_table[(crc32c_before ^ buffer[offset]) & 0xff] ^ (crc32c_before >> 8);
      #endif
    }

    for (unsigned offset = 0; offset < chunk_size; offset += 16 * 4) {

      // Get more of the keystream
      uint64_t keystream[2 * 4];
      speck_encrypt4(nonce_and_counter, schedule, keystream);
      nonce_and_counter[4] += 4;
      nonce_and_counter[5] += 4;
      nonce_and_counter[6] += 4;
      nonce_and_counter[7] += 4;

      // XOR buffer with keystream
      // Same byte order as in Words64ToBytes() from implementation guide
      for (unsigned i = 0; i < 8; i++) {
        buffer[offset + i + 0 * 8] ^= keystream[0] >> (i * 8);
        buffer[offset + i + 1 * 8] ^= keystream[4] >> (i * 8);
        buffer[offset + i + 2 * 8] ^= keystream[1] >> (i * 8);
        buffer[offset + i + 3 * 8] ^= keystream[5] >> (i * 8);
        buffer[offset + i + 4 * 8] ^= keystream[2] >> (i * 8);
        buffer[offset + i + 5 * 8] ^= keystream[6] >> (i * 8);
        buffer[offset + i + 6 * 8] ^= keystream[3] >> (i * 8);
        buffer[offset + i + 7 * 8] ^= keystream[7] >> (i * 8);
      }
    }

    // Update CRC32C after processing
    for (unsigned offset = 0; offset < chunk_size; offset++) {
      #if defined(__AVX2__)
        crc32c_after = _mm_crc32_u8(crc32c_after, buffer[offset]);
      #else
        crc32c_after = crc32c_table[(crc32c_after ^ buffer[offset]) & 0xff] ^ (crc32c_after >> 8);
      #endif
    }

    // Write processed buffer back
    f.write(&buffer[0], chunk_size);
    if (!f.good()) {
      std::cerr << "\nError writing " << filename << "\n";
      return 4;
    }
    remaining_length -= chunk_size;

    // Update progress bar if needed 
    auto notches_remaining = total_notches - (unsigned)(((double)length - remaining_length) * total_notches / length);
    if (total_notches - notches_shown > notches_remaining) {
      auto notches_to_show = total_notches - notches_shown - notches_remaining;
      while (notches_to_show--) {
        std::cerr << "o";
        notches_shown++;
      }
    }
  }
  std::cerr << "\r ";
  for (unsigned i = 0; i < total_notches; i++) {
    std::cerr << ' ';
  }
  std::cerr << " \r";
  crc32c_before = ~crc32c_before;
  crc32c_after = ~crc32c_after;
  if (restore) {
    return 0;
  } 
  if (append_suffix) {
    uint64_t suffix[2] = { (((uint64_t)crc32c_before) << 32) | (uint64_t)crc32c_before, nonce };
    // Encrypt suffix on nonce = counter = -1
    const uint64_t all_ones[2]  = { 0xffffffffffffffffULL, 0xffffffffffffffffULL };
    uint64_t gamma[2];
    speck_encrypt(all_ones, schedule, gamma);
    suffix[0] ^= gamma[0];
    suffix[1] ^= gamma[1];
    f.write((char*)(&suffix[0]), 16);
    if (!f.good()) {
      std::cerr << "\nError writing suffix\n";
      return 3;
    }
    f.close();
    std::string new_filename(filename);
    new_filename.append(".encrypted");
    if (rename(filename, new_filename.c_str())) {
      std::cerr << "Error renaming " << filename << " to " << new_filename << "\n";
      return 7;  
    }
    return 0;
  }
  f.close();
  if (check_checksum) {
    // Legacy checksum from plainext CRC32C, ciphertext CRC32C, and file length
    uint64_t checksum_in[2];
    // Upper: ciphertext CRC32C (before decryption). Lower: plaintext CRC32C (after decryption) 
    checksum_in[0] = (((uint64_t)crc32c_before) << 32) | (uint64_t)crc32c_after;
    checksum_in[1] = (uint64_t)length;
    // Encrypt on the same key
    uint64_t checksum_out[2];
    speck_encrypt(checksum_in, schedule, checksum_out);
    // Take the lowest 32 bits
    uint32_t checksum = (uint32_t)(checksum_out[0]);

    if (checksum != expected_checksum) {
      std::cerr << "Checksum mismatch: expected 0x" << std::hex << expected_checksum << ", got 0x" << checksum << "\n";  
      return 5;
    } else {
      std::string new_filename(filename);
      new_filename = new_filename.substr(0, p - 10 - filename);
      if (rename(filename, new_filename.c_str())) {
        std::cerr << "Error renaming " << filename << " to " << new_filename << "\n";
        return 6;  
      }
      return 0;
    }
  }
  if (check_crc32c) {
    if (expected_crc32c != crc32c_after) {
      std::cerr << "CRC32C mismatch: expected 0x" << std::hex << expected_crc32c << ", got 0x" << crc32c_after << "\n";  
      return 5;      
    } else { 
      std::string new_filename(filename);
      new_filename = new_filename.substr(0, p - 9 - filename);
      if (rename(filename, new_filename.c_str())) {
        std::cerr << "Error renaming " << filename << " to " << new_filename << "\n";
        return 6;  
      } 
      if (truncate(new_filename.c_str(), length - 16)) {
        std::cerr << "Error truncating " << new_filename << "\n";
        return 6;
      }
    }
  }
  return 0;
}

int main(int argc, char** argv)
{
  // When called without filename(s), run self-test using published test vectors and show usage
  if (argc <= 1) {
    const uint64_t key[4]       = { 0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL
                                  , 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL };
    const uint64_t plaintext[2] = { 0x202e72656e6f6f70ULL, 0x65736f6874206e49ULL };
    const uint64_t expected[2]  = { 0x4eeeb48d9c188f43ULL, 0x4109010405c0f53eULL };
    uint64_t schedule[34];
    speck_schedule(key, schedule);
    uint64_t observed[2];
    speck_encrypt(plaintext, schedule, observed);
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
  	std::cerr << "Usage:\n\n\tcryptolocker file1 [file2] [...]\n\n"
  	  "Encrypt or decrypt given file or files with Speck128/256 in counter mode.\n"
      "Password can be passed via environment variable CRYPTOLOCKER_PASSWORD.\n";
    #if defined(__AVX2__)
      std::cerr << "Will use SSE4.2 and AVX2 instructions.\n";
    #endif
  	return 0;
  }

  std::string first_attempt;
  const char* password = std::getenv("CRYPTOLOCKER_PASSWORD");
  if (!password) {
    std::cerr << "Enter encryption key (32 chars max): ";
    std::getline (std::cin, first_attempt);
    std::cerr << "Enter encryption key again         : ";
    std::string second_attempt;
    std::getline (std::cin, second_attempt);
    if (first_attempt.compare(second_attempt) != 0) {
      std::cerr << "Keys don't match\n";
      return -1;
    }
    password = first_attempt.c_str();
  } else {
    std::cerr << "Using password from environment variable\n";
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

  // Prepare key schedule
  uint64_t schedule[34];
  speck_schedule(k, schedule);

  // Iterate over the given files (can be more than one)
  unsigned ok_ct = 0, fail_ct = 0;
  for (int i = 1; i < argc; i++) {
    auto result = process_one_file(argv[i], schedule);
    if (result == 5) {
      // Decrypted on the wrong key (checksum mismatch). 
      // Restore by encrypting again, without checking checksum.
      // Should only happen when file length is used as nonce (backward compatibility).
      // Now that CRC32C is stored in the suffix rather than file name,
      // incorrect password can be identified before decryption. 
      process_one_file(argv[i], schedule, true);
    }
    if (result) {
      fail_ct++;
    } else {
      ok_ct++;
    }
  }
  if (ok_ct + fail_ct > 1) {
    std::cerr << (ok_ct + fail_ct) << " files, " << fail_ct << " errors\n";
  }
  return 0;
}
