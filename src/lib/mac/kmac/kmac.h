/*
* KMAC
* (C) 2023 Falko Strenzke
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KMAC_H_
#define BOTAN_KMAC_H_

#include <botan/mac.h>
#include <botan/hash.h>

namespace Botan {

/**
* KMAC256
*/
class KMAC256 final : public MessageAuthenticationCode
   {
   public:
      void clear() override;
      std::string name() const override;
      std::unique_ptr<MessageAuthenticationCode> new_object() const override;

      size_t output_length() const override;

      Key_Length_Specification key_spec() const override;

      /**
      * @param hash the hash to use for KMAC256ing
      */
      explicit KMAC256();

      KMAC256(const KMAC256&) = delete;
      KMAC256& operator=(const KMAC256&) = delete;
   private:
      void add_data(const uint8_t[], size_t) override;
      void final_result(uint8_t[]) override;
      void key_schedule(const uint8_t[], size_t) override;

      size_t m_output_length;

      std::unique_ptr<HashFunction> m_hash;
   };

}

#endif

