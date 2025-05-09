#pragma once

#include <string>
#include <vector>
#include <array>
#include <functional>
#include <cstdint>

class HMAC {
public:
    static std::vector<uint8_t> sha1(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message) {
        return hmac(key, message, sha1_hash);
    }

private:
    using HashFunction = std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)>;

    static std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, 
                                    const std::vector<uint8_t>& message,
                                    const HashFunction& hash_func) {
        const size_t block_size = 64; // SHA-1 block size
        std::vector<uint8_t> key_padded = key;

        // If key is longer than block size, hash it
        if (key_padded.size() > block_size) {
            key_padded = hash_func(key_padded);
        }

        // Pad key with zeros
        key_padded.resize(block_size, 0);

        // Create inner and outer padding
        std::vector<uint8_t> inner_padding(block_size, 0x36);
        std::vector<uint8_t> outer_padding(block_size, 0x5c);

        // XOR key with inner/outer padding
        for (size_t i = 0; i < block_size; ++i) {
            inner_padding[i] ^= key_padded[i];
            outer_padding[i] ^= key_padded[i];
        }

        // Inner hash
        std::vector<uint8_t> inner_hash_input;
        inner_hash_input.insert(inner_hash_input.end(), inner_padding.begin(), inner_padding.end());
        inner_hash_input.insert(inner_hash_input.end(), message.begin(), message.end());
        std::vector<uint8_t> inner_hash = hash_func(inner_hash_input);

        // Outer hash
        std::vector<uint8_t> outer_hash_input;
        outer_hash_input.insert(outer_hash_input.end(), outer_padding.begin(), outer_padding.end());
        outer_hash_input.insert(outer_hash_input.end(), inner_hash.begin(), inner_hash.end());
        return hash_func(outer_hash_input);
    }

    static std::vector<uint8_t> sha1_hash(const std::vector<uint8_t>& input) {
        // SHA-1 implementation
        uint32_t h0 = 0x67452301;
        uint32_t h1 = 0xEFCDAB89;
        uint32_t h2 = 0x98BADCFE;
        uint32_t h3 = 0x10325476;
        uint32_t h4 = 0xC3D2E1F0;

        // Pre-processing
        std::vector<uint8_t> message = input;
        size_t original_length = message.size() * 8;
        
        // Append padding
        message.push_back(0x80);
        while ((message.size() * 8 + 64) % 512 != 0) {
            message.push_back(0);
        }

        // Append length
        for (int i = 0; i < 8; ++i) {
            message.push_back((original_length >> ((7 - i) * 8)) & 0xFF);
        }

        // Process message in 512-bit chunks
        for (size_t i = 0; i < message.size(); i += 64) {
            std::array<uint32_t, 80> w;
            
            // Copy chunk into first 16 words
            for (int j = 0; j < 16; ++j) {
                w[j] = (message[i + j * 4] << 24) |
                       (message[i + j * 4 + 1] << 16) |
                       (message[i + j * 4 + 2] << 8) |
                       (message[i + j * 4 + 3]);
            }

            // Extend the first 16 words into the remaining 64 words
            for (int j = 16; j < 80; ++j) {
                w[j] = left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            }

            // Initialize hash value for this chunk
            uint32_t a = h0;
            uint32_t b = h1;
            uint32_t c = h2;
            uint32_t d = h3;
            uint32_t e = h4;

            // Main loop
            for (int j = 0; j < 80; ++j) {
                uint32_t f, k;
                if (j < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                } else if (j < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (j < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                uint32_t temp = left_rotate(a, 5) + f + e + k + w[j];
                e = d;
                d = c;
                c = left_rotate(b, 30);
                b = a;
                a = temp;
            }

            // Add this chunk's hash to result
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
        }

        // Produce the final hash value
        std::vector<uint8_t> hash;
        hash.reserve(20);
        for (uint32_t h : {h0, h1, h2, h3, h4}) {
            hash.push_back((h >> 24) & 0xFF);
            hash.push_back((h >> 16) & 0xFF);
            hash.push_back((h >> 8) & 0xFF);
            hash.push_back(h & 0xFF);
        }
        return hash;
    }

    static uint32_t left_rotate(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }
}; 