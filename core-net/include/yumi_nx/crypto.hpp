#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yumi_nx::net::crypto {

/// Cryptographically secure random bytes (Switch csrng / Windows BCryptGenRandom).
bool RandomBytes(uint8_t* out, size_t len) noexcept;

/// Constant-time byte comparison.
[[nodiscard]] bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len) noexcept;

// --- Hash Functions & Checksums ---

struct Md5 {
    void Init() noexcept;
    void Update(const void* data, size_t len) noexcept;
    void Final(uint8_t out[16]) noexcept;
    static void Digest(const void* data, size_t len, uint8_t out[16]) noexcept;

private:
    uint32_t state_[4]{};
    uint64_t total_bytes_ = 0;
    uint8_t buf_[64]{};
    size_t buf_len_ = 0;
};

struct Sha1 {
    void Init() noexcept;
    void Update(const void* data, size_t len) noexcept;
    void Final(uint8_t out[20]) noexcept;
    static void Digest(const void* data, size_t len, uint8_t out[20]) noexcept;

private:
    uint32_t state_[5]{};
    uint64_t total_bytes_ = 0;
    uint8_t buf_[64]{};
    size_t buf_len_ = 0;
};

struct Sha224 {
    static void Digest(const void* data, size_t len, uint8_t out[28]) noexcept;
};

struct Sha256 {
    void Init() noexcept;
    void Update(const void* data, size_t len) noexcept;
    void Final(uint8_t out[32]) noexcept;
    static void Digest(const void* data, size_t len, uint8_t out[32]) noexcept;

private:
    uint32_t state_[8]{};
    uint64_t total_bytes_ = 0;
    uint8_t buf_[64]{};
    size_t buf_len_ = 0;
};

struct Sha512 {
    void Init(bool is_sha384 = false) noexcept;
    void Update(const void* data, size_t len) noexcept;
    void Final(uint8_t* out, size_t out_len) noexcept;
    static void Digest512(const void* data, size_t len, uint8_t out[64]) noexcept;
    static void Digest384(const void* data, size_t len, uint8_t out[48]) noexcept;

private:
    uint64_t state_[8]{};
    uint64_t total_lo_ = 0;
    uint64_t total_hi_ = 0;
    uint8_t buf_[128]{};
    size_t buf_len_ = 0;
};

struct Blake2s {
    void Init(size_t out_len = 32, const uint8_t* key = nullptr, size_t key_len = 0) noexcept;
    void Update(const void* data, size_t len) noexcept;
    void Final(uint8_t* out) noexcept;
    static void Digest(const uint8_t* key, size_t key_len, const void* data, size_t len, uint8_t* out, size_t out_len) noexcept;

private:
    uint32_t h_[8]{};
    uint32_t t_[2]{};
    uint8_t buf_[64]{};
    size_t buf_len_ = 0;
    size_t out_len_ = 32;
};

struct Blake2b {
    void Init(size_t out_len = 64, const uint8_t* key = nullptr, size_t key_len = 0) noexcept;
    void Update(const void* data, size_t len) noexcept;
    void Final(uint8_t* out) noexcept;
    static void Digest(const uint8_t* key, size_t key_len, const void* data, size_t len, uint8_t* out, size_t out_len) noexcept;

private:
    uint64_t h_[8]{};
    uint64_t t_[2]{};
    uint8_t buf_[128]{};
    size_t buf_len_ = 0;
    size_t out_len_ = 64;
};

struct Shake128 {
    void Init() noexcept;
    void Update(const void* data, size_t len) noexcept;
    void Final() noexcept;
    void Squeeze(uint8_t* out, size_t len) noexcept;

private:
    uint64_t state_[25]{};
    size_t pos_ = 0;
    bool finalized_ = false;
};

struct Blake3 {
    void Init() noexcept;
    void InitKeyed(const uint8_t key[32]) noexcept;
    void InitDeriveKey(std::string_view context) noexcept;
    void Update(const void* data, size_t len) noexcept;
    void Final(uint8_t* out, size_t out_len = 32) const noexcept;

    static void Digest(const void* data, size_t len, uint8_t* out, size_t out_len = 32) noexcept;
    static void DigestKeyed(const uint8_t key[32], const void* data, size_t len, uint8_t* out, size_t out_len = 32) noexcept;
    static void DeriveKey(std::string_view context, const void* material, size_t mat_len, uint8_t* out, size_t out_len = 32) noexcept;

private:
    static constexpr size_t kMaxDepth = 54;
    void InitWithKeyWords(const uint32_t key_words[8], uint32_t flags) noexcept;
    void AddChunkChainingValue(uint32_t cv[8], uint64_t total_chunks) noexcept;

    uint32_t key_words_[8]{};
    uint32_t flags_ = 0;
    uint32_t chunk_cv_[8]{};
    uint64_t chunk_counter_ = 0;
    uint8_t chunk_buf_[64]{};
    uint8_t chunk_buf_len_ = 0;
    uint8_t chunk_blocks_compressed_ = 0;
    uint32_t cv_stack_[kMaxDepth][8]{};
    uint8_t cv_stack_len_ = 0;
};

[[nodiscard]] uint32_t Crc32Ieee(const void* data, size_t len) noexcept;
[[nodiscard]] uint32_t Fnv1a32(const void* data, size_t len) noexcept;

// --- MAC / KDF ---

void HmacSha1(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[20]) noexcept;
void HmacSha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[32]) noexcept;
void HmacSha384(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[48]) noexcept;
void HmacSha512(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[64]) noexcept;

void HkdfExtractSha1(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[20]) noexcept;
bool HkdfExpandSha1(const uint8_t prk[20], const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) noexcept;
void EvpBytesToKeyMd5(const uint8_t* pass, size_t pass_len, uint8_t* out_key, size_t key_len) noexcept;

void HkdfExtractSha256(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[32]) noexcept;
bool HkdfExpandSha256(const uint8_t prk[32], const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) noexcept;

void HkdfExtractSha384(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[48]) noexcept;
bool HkdfExpandSha384(const uint8_t prk[48], const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) noexcept;

bool Tls13HkdfExpandLabel(bool use_sha384,
                          const uint8_t* secret,
                          std::string_view label,
                          const uint8_t* context,
                          size_t context_len,
                          uint8_t* out,
                          size_t out_len) noexcept;

// --- Asymmetric ECDH ---

/// RFC 7748 scalar multiplication on Curve25519. Returns false only if output is all-zero low-order point.
bool X25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u_coord[32]) noexcept;
void X25519Base(uint8_t out_pub[32], const uint8_t scalar[32]) noexcept;

/// NIST P-256 (secp256r1) ECDH & X.509 SubjectPublicKeyInfo DER (91 bytes).
struct P256KeyPair {
    uint8_t priv[32]{};
    uint8_t pub65[65]{};  // uncompressed 04 || X(32) || Y(32)
};

bool P256GenerateKeyPair(P256KeyPair& out) noexcept;
bool P256PublicFromPrivate(const uint8_t priv[32], uint8_t out_pub65[65]) noexcept;
bool P256Ecdh(uint8_t out_shared32[32], const uint8_t priv[32], const uint8_t peer_pub65[65]) noexcept;
std::vector<uint8_t> P256EncodeSpkiDer(const uint8_t pub65[65]);
bool P256DecodeSpkiDer(const uint8_t* der, size_t len, uint8_t out_pub65[65]) noexcept;

// --- Block / Stream / AEAD Ciphers ---

bool AesEcbEncryptBlock(const uint8_t* key, size_t key_len, const uint8_t in[16], uint8_t out[16]) noexcept;
void ChaCha20Xor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], const uint8_t* in, size_t len, uint8_t* out) noexcept;

bool AesGcmEncrypt(const uint8_t* key,
                   size_t key_len,  // 16 or 32
                   const uint8_t iv[12],
                   const uint8_t* aad,
                   size_t aad_len,
                   const uint8_t* pt,
                   size_t len,
                   uint8_t* ct,
                   uint8_t tag[16]) noexcept;

bool AesGcmDecrypt(const uint8_t* key,
                   size_t key_len,  // 16 or 32
                   const uint8_t iv[12],
                   const uint8_t* aad,
                   size_t aad_len,
                   const uint8_t* ct,
                   size_t len,
                   const uint8_t tag[16],
                   uint8_t* pt) noexcept;

bool ChaCha20Poly1305Encrypt(const uint8_t key[32],
                             const uint8_t nonce[12],
                             const uint8_t* aad,
                             size_t aad_len,
                             const uint8_t* pt,
                             size_t len,
                             uint8_t* ct,
                             uint8_t tag[16]) noexcept;

bool ChaCha20Poly1305Decrypt(const uint8_t key[32],
                             const uint8_t nonce[12],
                             const uint8_t* aad,
                             size_t aad_len,
                             const uint8_t* ct,
                             size_t len,
                             const uint8_t tag[16],
                             uint8_t* pt) noexcept;

// --- Text Codecs ---

std::string Base64Encode(const uint8_t* data, size_t len, bool url_safe = false, bool padding = true);
std::optional<std::vector<uint8_t>> Base64Decode(std::string_view input);
std::string HexEncode(const uint8_t* data, size_t len);
std::optional<std::vector<uint8_t>> HexDecode(std::string_view hex);
bool ParseUuidBytes(std::string_view uuid, uint8_t out[16]) noexcept;

}  // namespace yumi_nx::net::crypto
