/*
* KMAC
* (C) 2023 Falko Strenzke
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/kmac.h>
#include <botan/exceptn.h>

namespace Botan {

/**
* KMAC
* https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf
*/

void KMAC256::clear()
   {

   }
std::string KMAC256::name() const
   {
   return std::string("KMAC-256");
   }
std::unique_ptr<MessageAuthenticationCode> KMAC256::new_object() const
   {
   return std::make_unique<KMAC256>();
   }

size_t KMAC256::output_length() const
   {
   return m_output_length;
   }

Key_Length_Specification KMAC256::key_spec() const
   {
   // TODO: NEED TO ADJUST:
   return Key_Length_Specification(0, 4096);
   }

/**
* @param hash the hash to use for KMAC256ing
*/
KMAC256::KMAC256()
   :m_output_length(32)
   {

   }

void KMAC256::add_data(unsigned char const*, unsigned long)
   {
   throw Internal_Error("not implemented");
   }

void KMAC256::final_result(unsigned char*)
   {
   throw Internal_Error("not implemented");
   }


void KMAC256::key_schedule(const uint8_t[], size_t)
   {
   throw Internal_Error("not implemented");
   }
}
