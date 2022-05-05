/*
* SHAKE-128 as a stream cipher
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHAKE128_CIPHER_H_
#define BOTAN_SHAKE128_CIPHER_H_

#include <botan/stream_cipher.h>
#include <botan/secmem.h>

namespace Botan {

/**
* Base class for SHAKE-based XOFs presented as a stream cipher
*/
class SHAKE_Cipher : public StreamCipher
   {
   public:
      explicit SHAKE_Cipher(size_t shake_rate);

      /**
      * Produce more XOF output
      */
      void cipher(const uint8_t in[], uint8_t out[], size_t length) override;

      /**
      * Seeking is not supported, this function will throw
      */
      void seek(uint64_t offset) override;

      /**
      * IV not supported, this function will throw unless iv_len == 0
      */
      void set_iv(const uint8_t iv[], size_t iv_len) override;

      void clear() override;

   private:
      void key_schedule(const uint8_t key[], size_t key_len) override;

   protected:
      size_t m_shake_rate;

      secure_vector<uint64_t> m_state; // internal state
      secure_vector<uint8_t> m_buffer; // ciphertext buffer
      size_t m_buf_pos; // position in m_buffer
   };

class SHAKE_128_Cipher : public SHAKE_Cipher
   {
   public:
      SHAKE_128_Cipher();

      std::string name() const override
         { return "SHAKE-128"; }

      std::unique_ptr<StreamCipher> new_object() const override
         { return std::make_unique<SHAKE_128_Cipher>(); }

      Key_Length_Specification key_spec() const override;
   };

class SHAKE_256_Cipher : public SHAKE_Cipher
   {
   public:
      SHAKE_256_Cipher();

      std::string name() const override
         { return "SHAKE-256"; }

      std::unique_ptr<StreamCipher> new_object() const override
         { return std::make_unique<SHAKE_256_Cipher>(); }

      Key_Length_Specification key_spec() const override;
   };

}

#endif
