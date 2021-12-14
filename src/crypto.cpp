/* Copyright 2015 OpenMarket Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "olm/crypto.h"
#include "olm/memory.hh"

#include <cstring>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#include "ed25519/src/ed25519.h"

namespace {

static const std::uint8_t CURVE25519_BASEPOINT[32] = {9};
static const std::size_t AES_KEY_SCHEDULE_LENGTH = 60;
static const std::size_t AES_KEY_BITS = 8 * AES256_KEY_LENGTH;
static const std::size_t AES_BLOCK_LENGTH = 16;
static const std::size_t SHA256_BLOCK_LENGTH = 64;
static const std::uint8_t HKDF_DEFAULT_SALT[32] = {};

template <typename T>
inline T checked(T val) {
    if (!val) {
        abort();
    }
    return val;
}

template <>
inline int checked(int val) {
    if (val <= 0) {
        abort();
    }
    return val;
}

} // namespace

void _olm_crypto_curve25519_generate_key(
    uint8_t const * random_32_bytes,
    struct _olm_curve25519_key_pair *key_pair
) {
    EVP_PKEY *pkey = checked(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                             random_32_bytes, 32));
    size_t priv_len = CURVE25519_KEY_LENGTH;
    size_t pub_len = CURVE25519_KEY_LENGTH;
    checked(EVP_PKEY_get_raw_private_key(pkey, key_pair->private_key.private_key, &priv_len));
    checked(EVP_PKEY_get_raw_public_key(pkey, key_pair->public_key.public_key, &pub_len));
    EVP_PKEY_free(pkey);
}


void _olm_crypto_curve25519_shared_secret(
    const struct _olm_curve25519_key_pair *our_key,
    const struct _olm_curve25519_public_key * their_key,
    std::uint8_t * output
) {
    EVP_PKEY *pkey = checked(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                             our_key->private_key.private_key, CURVE25519_KEY_LENGTH));
    EVP_PKEY *peer = checked(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                             their_key->public_key, CURVE25519_KEY_LENGTH));
    EVP_PKEY_CTX *ctx = checked(EVP_PKEY_CTX_new(pkey, nullptr));
    checked(EVP_PKEY_derive_init(ctx));
    checked(EVP_PKEY_derive_set_peer(ctx, peer));
    size_t shared_secret_length = CURVE25519_SHARED_SECRET_LENGTH;
    checked(EVP_PKEY_derive(ctx, output, &shared_secret_length));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(pkey);
}


void _olm_crypto_ed25519_generate_key(
    std::uint8_t const * random_32_bytes,
    struct _olm_ed25519_key_pair *key_pair
) {
    ::ed25519_create_keypair(
        key_pair->public_key.public_key, key_pair->private_key.private_key,
        random_32_bytes
    );
}


void _olm_crypto_ed25519_sign(
    const struct _olm_ed25519_key_pair *our_key,
    std::uint8_t const * message, std::size_t message_length,
    std::uint8_t * output
) {
    ::ed25519_sign(
        output,
        message, message_length,
        our_key->public_key.public_key,
        our_key->private_key.private_key
    );
}


int _olm_crypto_ed25519_verify(
    const struct _olm_ed25519_public_key *their_key,
    std::uint8_t const * message, std::size_t message_length,
    std::uint8_t const * signature
) {
    return 0 != ::ed25519_verify(
        signature,
        message, message_length,
        their_key->public_key
    );
}


std::size_t _olm_crypto_aes_encrypt_cbc_length(
    std::size_t input_length
) {
    return input_length + AES_BLOCK_LENGTH - input_length % AES_BLOCK_LENGTH;
}


void _olm_crypto_aes_encrypt_cbc(
    _olm_aes256_key const *key,
    _olm_aes256_iv const *iv,
    std::uint8_t const * input, std::size_t input_length,
    std::uint8_t * output
) {
    EVP_CIPHER_CTX* ctx = checked(EVP_CIPHER_CTX_new());
    checked(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key->key, iv->iv));
    int output_length[2];
    checked(EVP_EncryptUpdate(ctx, output, &output_length[0], input, input_length));
    checked(EVP_EncryptFinal_ex(ctx, output + output_length[0], &output_length[1]));
    EVP_CIPHER_CTX_free(ctx);
}


std::size_t _olm_crypto_aes_decrypt_cbc(
    _olm_aes256_key const *key,
    _olm_aes256_iv const *iv,
    std::uint8_t const * input, std::size_t input_length,
    std::uint8_t * output
) {
    EVP_CIPHER_CTX* ctx = checked(EVP_CIPHER_CTX_new());
    checked(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key->key, iv->iv));
    int output_length[2];
    checked(EVP_DecryptUpdate(ctx, output, &output_length[0], input, input_length));
    checked(EVP_DecryptFinal_ex(ctx, output + output_length[0], &output_length[1]));
    EVP_CIPHER_CTX_free(ctx);
    return output_length[0] + output_length[1];
}


void _olm_crypto_sha256(
    std::uint8_t const * input, std::size_t input_length,
    std::uint8_t * output
) {
    checked(EVP_Digest(input, input_length, output, nullptr, EVP_sha256(), nullptr));
}


void _olm_crypto_hmac_sha256(
    std::uint8_t const * key, std::size_t key_length,
    std::uint8_t const * input, std::size_t input_length,
    std::uint8_t * output
) {
    checked(HMAC(EVP_sha256(), key, key_length, input, input_length, output, nullptr));
}


void _olm_crypto_hkdf_sha256(
    std::uint8_t const * input, std::size_t input_length,
    std::uint8_t const * salt, std::size_t salt_length,
    std::uint8_t const * info, std::size_t info_length,
    std::uint8_t * output, std::size_t output_length
) {
    EVP_PKEY_CTX *pctx = checked(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL));
    checked(EVP_PKEY_derive_init(pctx));
    checked(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()));

    if (input_length) {
        checked(EVP_PKEY_CTX_set1_hkdf_key(pctx, input, input_length));
    } else {
        /* OpenSSL HKDF doesn't directly support zero-length keys:
         * https://github.com/openssl/openssl/issues/8531
         * Do the extract step manually with HMAC and use HKDF only for expand */
        uint8_t intermediate[SHA256_OUTPUT_LENGTH];
        checked(HMAC(EVP_sha256(), nullptr, 0, salt, salt_length, intermediate, nullptr));
        checked(EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY));
        checked(EVP_PKEY_CTX_set1_hkdf_key(pctx, intermediate, sizeof(intermediate)));
    }

    checked(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_length));
    checked(EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_length));
    checked(EVP_PKEY_derive(pctx, output, &output_length));
    EVP_PKEY_CTX_free(pctx);
}
