/*
* KMAC
* (C) 2023 Falko Strenzke
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "botan/secmem.h"
#include "botan/exceptn.h"
#include "botan/assert.h"
#include <botan/internal/kmac.h>
#include <botan/internal/keccak.h>
#include <botan/exceptn.h>
#include <botan/secmem.h>
#include <botan/types.h>
#include <limits>
#include <vector>

//TODO: remove
#include <iostream>
#include <botan/hex.h>

namespace Botan {

/**
* KMAC
* https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf
*
*
* newX = bytepad(encode_string(K), 136) ‖ input ‖ right_encode(L)
* T = bytebad(encode_string("KMAC" ‖ encode_string(S), 136))  // S = nonce
* return Keccak[512](T ‖ newX ‖ 00, L)
*
*/

// regarding the interface see https://github.com/randombit/botan/issues/3262
//
//

namespace {

template < bool IS_LEFT_ENCODE, typename T>
void left_or_right_encode(size_t s, T& output_container)
   {
   int i;
   // determine number of octets needed to encode s
   for(i = sizeof(s); i > 0; i--)
      {
      uint8_t t = (s >> ((i-1)*8) & static_cast<size_t>(0xFF)  );
      if(t != 0)
         {
         break;
         }
      }
   if(i == 0)
   {
       i = 1;
   }
   std::cout << "first loop: i = " << i << std::endl;
   if(IS_LEFT_ENCODE)
      {
      output_container.push_back(i);
      }
   // big endian encoding of s
   for(int j = i; j > 0; j--)
      {
      output_container.push_back(s >> (j-1)*8 & (static_cast<size_t>(0xFF)  ));
      }
   if(!IS_LEFT_ENCODE)
      {
      output_container.push_back(i);
      }
   }

template <typename T>
void left_encode(size_t s, T& output_container)
   {
   return left_or_right_encode<true>(s, output_container);
   }

template <typename T>
void right_encode(size_t s, T& output_container)
   {
   return left_or_right_encode<false>(s, output_container);
   }

void test_left_encode()
   {
   std::vector<uint8_t> exp_res = {0x02, 0x01, 0x00};
   std::vector<uint8_t> result;
   left_encode(256, result);
   if(exp_res != result)
      {
      //std::cerr << "error for left_encode: result = " << hex_encode(result) << std::endl;
      throw Botan::Internal_Error("invalid self test result for left_encode: " + hex_encode(result));
      }
   }


void test_right_encode()
   {
   std::vector<uint8_t> exp_res = {0x00, 0x01};
   std::vector<uint8_t> result;
   right_encode(0, result);
   if(exp_res != result)
      {
      std::cerr << "error for right_encode: result = " << hex_encode(result) << std::endl;
      throw Botan::Internal_Error("invalid self test result for right_encode");
      }
   }

size_t byte_len_from_bit_len(size_t bit_length)
   {
   if(bit_length % 8)
      {
      throw Invalid_Argument("cannot convert byte length to bit length that is not a multiple of 8");
      }
   return bit_length / 8;
   }

size_t bit_len_from_byte_len(size_t byte_length)
   {

   size_t bit_length = 8*byte_length;
   if(bit_length < byte_length)
      {
      throw Botan::Invalid_Argument("byte length is too large. Only byte lengths of up to "
                                    + std::to_string(std::numeric_limits<size_t>::max() / 8) + " are supported on this platform in this function.");
      }
   return bit_length;
   }

template <typename T>
void encode_string(const uint8_t* input, size_t input_byte_length, T& output_container)
   {
   // TODO: REMOVE TESTS:
   test_left_encode();
   test_right_encode();
   // END TESTS
   // left_encode(*bitlen* of input)
   left_encode(bit_len_from_byte_len(input_byte_length), output_container);
   output_container.insert(output_container.end(), input, &input[input_byte_length]);
   }

template <typename T>
void byte_pad(uint8_t input[], size_t input_byte_length, size_t w_in_bytes, T& output_container)
   {
   left_encode(w_in_bytes, output_container);
   output_container.insert(output_container.end(), input, &input[input_byte_length]);
   if(w_in_bytes > input_byte_length)
      {
      size_t nb_trail_zeroes = w_in_bytes - input_byte_length;
      std::vector<uint8_t> trailing_zeroes(nb_trail_zeroes, 0);
      output_container.insert(output_container.end(), &trailing_zeroes[0], &trailing_zeroes[trailing_zeroes.size()]);
      }

   }

}

void KMAC256::clear()
   {
   zap(m_key);
   m_key_set = false;
   m_hash->clear();
   }
std::string KMAC256::name() const
   {
   return std::string("KMAC-256");
   }
std::unique_ptr<MessageAuthenticationCode> KMAC256::new_object() const
   {
   return std::make_unique<KMAC256>(m_output_bit_length);
   }

size_t KMAC256::output_length() const
   {
   return m_output_bit_length/8;
   }

Key_Length_Specification KMAC256::key_spec() const
   {
   // KMAC support key lengths from zero up to 2²⁰⁴⁰ (2^(2040)) bits
   // https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf#page=28
   return Key_Length_Specification(0, std::numeric_limits<size_t>::max());
   }


void KMAC256::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   const uint8_t dom_sep [] = { 'K', 'M', 'A', 'C' };
   if(!m_key_set)
      {
      throw Internal_Error("key not set for KMAC, this should not happen");
      }
   std::vector<uint8_t> t_input;
   encode_string(dom_sep, sizeof(dom_sep), t_input);
   encode_string(nonce, nonce_len, t_input);
   std::vector<uint8_t> t;
   byte_pad(&t[0], t.size(), m_pad_byte_length, t);
   m_hash->update(t);
   secure_vector<uint8_t> key_input;
   encode_string(&m_key[0], m_key.size(), key_input);
   secure_vector<uint8_t> newX_head;
   byte_pad(&key_input[0], key_input.size(), m_pad_byte_length, newX_head);
   m_hash->update(newX_head);
   }

/**
* @param hash the hash to use for KMAC256ing
*/
KMAC256::KMAC256(uint32_t output_bit_length)
   :m_output_bit_length(output_bit_length),
    m_hash(new Keccak_1600(m_output_bit_length)),
    m_pad_byte_length(136)
   {
   if(!m_hash)
      {
      throw Internal_Error("could not instantiate Keccak-1600 for KMAC256, this should not happen");
      }
   // ensure valid output length
   byte_len_from_bit_len(m_output_bit_length);
   }

void KMAC256::add_data(unsigned char const* data, unsigned long data_len)
   {
   m_hash->update(data, data_len);
   }

void KMAC256::final_result(unsigned char* output)
   {
   std::vector<uint8_t> tail;
   right_encode(m_output_bit_length, tail);
   tail.push_back(0);
   m_hash->update(tail);
   std::vector<uint8_t> result;
   m_hash->final(result);
   BOTAN_ASSERT_EQUAL(result.size(),  m_output_bit_length/8, "consistent output length" );
   memcpy(output, &result[0], result.size());
   }


void KMAC256::key_schedule(const uint8_t key[], size_t key_length)
   {

   m_hash->clear();
   m_key.insert(m_key.end(), &key[0], &key[key_length]);
   m_key_set = true;
   }
}
