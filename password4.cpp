// password4.cpp
//
// Create unique password for a given identifier from predefined common seed
//
// Building:
//
//   g++ -O3 -Wall -Wextra -std=c++11 -g -o password4 password4.cpp
//
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <x86intrin.h>

static inline void
speck_round(uint64_t& x, uint64_t& y, const uint64_t k)
{
  x = __rorq(x, 8);
  x += y;
  x ^= k;
  y = __rolq(y, 3);
  y ^= x;
}

static void 
speck_encrypt( uint64_t data[2]
             , const uint64_t key[4]
             )
{
  uint64_t a = key[0];
  uint64_t bcd[3] = {key[1], key[2], key[3]};
  for (unsigned i = 0; i < 34; i++) {
    speck_round(data[1], data[0], a);
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

int main(int argc, char** argv)
{
  if (argc != 2) { // No arguments, do a self-check and show usage
    const uint64_t key[4]       = { 0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL
                                  , 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL };
    const uint64_t plaintext[2] = { 0x202e72656e6f6f70ULL, 0x65736f6874206e49ULL };
    const uint64_t expected[2]  = { 0x4eeeb48d9c188f43ULL, 0x4109010405c0f53eULL };
    uint64_t observed[2]; observed[0] = plaintext[0]; observed[1] = plaintext[1];
    speck_encrypt(observed, key);
    if ( expected[0] != observed[0] 
      || expected[1] != observed[1]
       ) {
      std::cerr << "speck_encrypt() self-test failed\n" 
                << "Expected 0x" << std::hex << expected[0] << ", 0x" << expected[1] << "\n"
                << "Observed 0x" << observed[0] << ", 0x" << observed[1] << "\n";
       return 1;
    }
    std::cerr << "Usage:\n\n\tpassword4 john.doe@example.com\n\n"
      "Creates base58-encoded password by encrypting FNV-1a hash of given identifier\n"
      "with Speck128/256 on the key passed in environmental variable CRYPTOLOCKER_PASSWORD.\n";
    return 0;
  }

  // Read the secret seed for use as encryption key
  char* seed = std::getenv("CRYPTOLOCKER_PASSWORD");
  if (!seed) {
    std::cerr << "Environmental variable CRYPTOLOCKER_PASSWORD is not defined\n";
    return 2;
  }
  uint64_t k[4] = { 0 };
  {
    unsigned bytes_left = strlen(seed);
    for (unsigned i = 0; i < 4; i++, bytes_left -= 8) {
      k[i] = bytes_to_uint64((uint8_t*)(seed + i * 8), bytes_left > 8 ? 8 : bytes_left);
      if (bytes_left <= 8) break;
    }
  }

  // Calculate FNV-1a hash of the input. Hash function does not have to be 
  // cryptographically strong because potential attacker cannot choose the input.
  // We just want to use all of the input and spread it across 128 bits to 
  // avoid collisions (same output for different inputs).
  uint64_t d[2] = { 0 };
  __uint128_t fnv_prime = 1; // FNV prime is 2**88 + 0x13b
  fnv_prime <<= 88;
  fnv_prime |= 0x13b;
  __uint128_t hash = fnv_prime;
  for (unsigned char* p = (unsigned char*)(argv[1]); *p; p++) {
    hash ^= *p;
    hash *= fnv_prime;
  }
  d[0] = (uint64_t)hash;
  hash >>= 64;
  d[1] = (uint64_t)hash;

  // Encrypt hashed input
  speck_encrypt(d, k);

  // Base58 encode the result, add separators, trim to desired length (19 characters total)
  __uint128_t x = d[1];
  x <<= 64;
  x |= d[0];
  const char base58[59] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  std::string buffer;
  do {
    buffer.insert(buffer.begin(), base58[x % 58]);
    switch (buffer.length()) {
      case 4: case 9: case 14:
        buffer.insert(buffer.begin(), '-');
    }
  } while ((x /= 58) && (buffer.length() < 19));
  std::cout << buffer << "\n";
  return 0;
}
