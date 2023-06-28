/*
* SHAKE-128/256 as a hash
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/shake.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/sha3.h>

namespace Botan {

SHAKE_128::SHAKE_128(size_t output_bits) : m_output_bits(output_bits), m_S(25), m_S_pos(0) {
   if(output_bits % 8 != 0) {
      throw Invalid_Argument(fmt("SHAKE_128: Invalid output length {}", output_bits));
   }
}

std::string SHAKE_128::name() const {
   return fmt("SHAKE-128({})", m_output_bits);
}

std::unique_ptr<HashFunction> SHAKE_128::new_object() const {
   return std::make_unique<SHAKE_128>(m_output_bits);
}

std::unique_ptr<HashFunction> SHAKE_128::copy_state() const {
   return std::make_unique<SHAKE_128>(*this);
}

void SHAKE_128::clear() {
   zeroise(m_S);
   m_S_pos = 0;
}

void SHAKE_128::add_data(const uint8_t input[], size_t length) {
   m_S_pos = Keccak_FIPS::absorb(SHAKE_128_BITRATE, m_S, m_S_pos, std::span(input, length));
}

void SHAKE_128::final_result(uint8_t output[]) {
   Keccak_FIPS::finish(SHAKE_128_BITRATE, m_S, m_S_pos, 0xF, 4);
   Keccak_FIPS::expand(SHAKE_128_BITRATE, m_S, std::span(output, output_length()));
   clear();
}

SHAKE_256::SHAKE_256(size_t output_bits) : m_output_bits(output_bits), m_S(25), m_S_pos(0) {
   if(output_bits % 8 != 0) {
      throw Invalid_Argument(fmt("SHAKE_256: Invalid output length {}", output_bits));
   }
}

std::string SHAKE_256::name() const {
   return fmt("SHAKE-256({})", m_output_bits);
}

std::unique_ptr<HashFunction> SHAKE_256::new_object() const {
   return std::make_unique<SHAKE_256>(m_output_bits);
}

std::unique_ptr<HashFunction> SHAKE_256::copy_state() const {
   return std::make_unique<SHAKE_256>(*this);
}

void SHAKE_256::clear() {
   zeroise(m_S);
   m_S_pos = 0;
}

void SHAKE_256::add_data(const uint8_t input[], size_t length) {
   m_S_pos = Keccak_FIPS::absorb(SHAKE_256_BITRATE, m_S, m_S_pos, std::span(input, length));
}

void SHAKE_256::final_result(uint8_t output[]) {
   Keccak_FIPS::finish(SHAKE_256_BITRATE, m_S, m_S_pos, 0xF, 4);
   Keccak_FIPS::expand(SHAKE_256_BITRATE, m_S, std::span(output, output_length()));

   clear();
}

}  // namespace Botan
