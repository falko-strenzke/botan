/*
* SHAKE-128
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/shake_cipher.h>
#include <botan/exceptn.h>
#include <botan/internal/sha3.h>
#include <botan/internal/loadstor.h>

namespace Botan {

SHAKE_Cipher::SHAKE_Cipher(size_t shake_rate) :
   m_shake_rate(shake_rate),
   m_buf_pos(0)
   {}

void SHAKE_Cipher::clear()
   {
   zap(m_state);
   zap(m_buffer);
   m_buf_pos = 0;
   }

void SHAKE_Cipher::set_iv(const uint8_t /*iv*/[], size_t length)
   {
   /*
   * This could be supported in some way (say, by treating iv as
   * a prefix or suffix of the key).
   */
   if(length != 0)
      { throw Invalid_IV_Length(name(), length); }
   }

void SHAKE_Cipher::seek(uint64_t /*offset*/)
   {
   throw Not_Implemented("SHAKE_Cipher::seek");
   }

void SHAKE_Cipher::cipher(const uint8_t in[], uint8_t out[], size_t length)
   {
   verify_key_set(m_state.empty() == false);

   while(length >= m_shake_rate - m_buf_pos)
      {
      xor_buf(out, in, &m_buffer[m_buf_pos], m_shake_rate - m_buf_pos);
      length -= (m_shake_rate - m_buf_pos);
      in += (m_shake_rate - m_buf_pos);
      out += (m_shake_rate - m_buf_pos);

      Keccak_FIPS_generic::permute(m_state.data());
      copy_out_le(m_buffer.data(), m_shake_rate, m_state.data());

      m_buf_pos = 0;
      }
   xor_buf(out, in, &m_buffer[m_buf_pos], length);
   m_buf_pos += length;
   }

void SHAKE_Cipher::key_schedule(const uint8_t key[], size_t length)
   {
   const size_t SHAKE_BITRATE = m_shake_rate*8;
   m_state.resize(25);
   m_buffer.resize(m_shake_rate);
   zeroise(m_state);

   const size_t S_pos = Keccak_FIPS_generic::absorb(SHAKE_BITRATE, m_state, 0, key, length);
   //SHA_3::finish(SHAKE_BITRATE, m_state, S_pos, 0x1F, 0x80);
   Keccak_FIPS_generic::finish(SHAKE_BITRATE, m_state, S_pos, 0xF,4);
   copy_out_le(m_buffer.data(), m_buffer.size(), m_state.data());
   }

SHAKE_128_Cipher::SHAKE_128_Cipher() : SHAKE_Cipher((1600-256)/8) {}

Key_Length_Specification SHAKE_128_Cipher::key_spec() const
   {
   return Key_Length_Specification(1, 160);
   }

SHAKE_256_Cipher::SHAKE_256_Cipher() : SHAKE_Cipher(136) {}

Key_Length_Specification SHAKE_256_Cipher::key_spec() const
   {
   // TODO: Does this need to differ from SHAKE-128??
   return Key_Length_Specification(1, 160);
   }

}
