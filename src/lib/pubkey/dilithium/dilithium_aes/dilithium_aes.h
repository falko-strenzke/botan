/*
* Asymmetric primitives for dilithium AES
* (C) 2022 Jack Lloyd
* (C) 2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DILITHIUM_AES_SYM_PRIMITIVES_H_
#define BOTAN_DILITHIUM_AES_SYM_PRIMITIVES_H_

#include <botan/internal/dilithium_symmetric_primitives.h>

#include <botan/stream_cipher.h>
#include <botan/internal/loadstor.h>

#include <array>
#include <memory>
#include <vector>

namespace Botan {

class Dilithium_AES_Symmetric_Primitives : public Dilithium_Symmetric_Primitives
   {
   public:
      // AES mode always uses AES-256, regardless of the XofType
      std::unique_ptr<StreamCipher> XOF(const XofType /* type */, const std::vector<uint8_t>& seed,
                                        uint16_t nonce) const final
         {
         auto cipher = StreamCipher::create_or_throw("CTR(AES-256)");

         // seed is used as key for the aes-ctr mode
         BOTAN_ASSERT_NOMSG(seed.size() >= cipher->key_spec().minimum_keylength());
         cipher->set_key(seed.data(), cipher->key_spec().minimum_keylength());

         // two bytes nonce is used as iv zero padded for the aes-ctr mode
         std::array<uint8_t, 2> iv { get_byte<1>(nonce), get_byte<0>(nonce) };
         cipher->set_iv(iv.data(), iv.size());
         return cipher;
         }

      secure_vector<uint8_t> ExpandMask(const secure_vector<uint8_t>& seed,
                                        uint16_t nonce, size_t out_len) const override
         {
         secure_vector<uint8_t> buf(out_len);
         auto cipher = StreamCipher::create_or_throw("CTR(AES-256)");

         BOTAN_ASSERT_NOMSG(seed.size() >= cipher->key_spec().minimum_keylength());
         cipher->set_key(seed.data(), cipher->key_spec().minimum_keylength());

         std::array<uint8_t, 2> iv { get_byte<1>(nonce), get_byte<0>(nonce) };
         cipher->set_iv(iv.data(), iv.size());

         std::vector<uint8_t> zero_input(out_len);
         cipher->cipher(zero_input.data(), buf.data(), out_len);

         return buf;
         }
   };

} // namespace Botan

#endif
