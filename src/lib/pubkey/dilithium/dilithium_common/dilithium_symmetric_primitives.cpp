/**
 * Asymmetric primitives for dilithium
 * (C) 2022 Jack Lloyd
 * (C) 2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/dilithium_symmetric_primitives.h>

#if defined(BOTAN_HAS_DILITHIUM)
   #include <botan/internal/dilithium_modern.h>
#endif

#if defined(BOTAN_HAS_DILITHIUM_AES)
   #include <botan/internal/dilithium_aes.h>
#endif

namespace Botan {

std::unique_ptr<Dilithium_Symmetric_Primitives> Dilithium_Symmetric_Primitives::create(DilithiumFlavor algo)
   {
   switch(algo)
      {
      case DilithiumFlavor::Randomized:
      case DilithiumFlavor::Deterministic:
#if defined(BOTAN_HAS_DILITHIUM)
         return std::make_unique<Dilithium_Common_Symmetric_Primitives>();
#else
         break;
#endif

      case DilithiumFlavor::AesDeterministic:
      case DilithiumFlavor::AesRandomized:
#if defined(BOTAN_HAS_DILITHIUM_AES)
         return std::make_unique<Dilithium_AES_Symmetric_Primitives>();
#else
         break;
#endif
      }

   throw Not_Implemented("requested Dilithium mode is not enabled in this build");
   }


DilithiumModeConstants::DilithiumModeConstants(DilithiumDimension dimension, DilithiumFlavor algo)
   : m_dimension(dimension)
   , m_algo(algo)
   , m_symmetric_primitives(Dilithium_Symmetric_Primitives::create(algo))
   {
   switch(m_algo)
      {
      case Botan::DilithiumFlavor::Randomized:
         m_use_randomize = true;
         [[fallthrough]];
      case Botan::DilithiumFlavor::Deterministic:
         m_stream128_blockbytes = DilithiumModeConstants::SHAKE128_RATE;
         m_stream256_blockbytes = DilithiumModeConstants::SHAKE256_RATE;
         break;
      case Botan::DilithiumFlavor::AesRandomized:
         m_use_randomize = true;
         [[fallthrough]];
      case Botan::DilithiumFlavor::AesDeterministic:
         m_use_aes = true;
         m_stream128_blockbytes = AES256CTR_BLOCKBYTES;
         m_stream256_blockbytes = AES256CTR_BLOCKBYTES;
         break;
      }
   switch(m_dimension)
      {
      case Botan::DilithiumDimension::Dilithium4x4:
         m_k = 4;
         m_l = 4;
         m_eta = DilithiumEta::Eta2;
         m_tau = 39;
         m_beta = 78;
         m_gamma1 = (1 << 17);
         m_gamma2 = ((DilithiumModeConstants::Q - 1) / 88);
         m_omega = 80;
         m_nist_security_strength = 2;
         m_polyz_packedbytes = 576;
         m_polyw1_packedbytes = 192;
         m_polyeta_packedbytes = 96;
         m_poly_uniform_eta_nblocks = ((136 + m_stream128_blockbytes - 1) / m_stream128_blockbytes);
         break;
      case Botan::DilithiumDimension::Dilithium6x5:
         m_k = 6;
         m_l = 5;
         m_eta = DilithiumEta::Eta4;
         m_tau = 49;
         m_beta = 196;
         m_gamma1 = (1 << 19);
         m_gamma2 = ((DilithiumModeConstants::Q - 1) / 32);
         m_omega = 55;
         m_nist_security_strength = 3;
         m_polyz_packedbytes = 640;
         m_polyw1_packedbytes = 128;
         m_polyeta_packedbytes = 128;
         m_poly_uniform_eta_nblocks = ((227 + m_stream128_blockbytes - 1) / m_stream128_blockbytes);
         break;
      case Botan::DilithiumDimension::Dilithium8x7:
         m_k = 8;
         m_l = 7;
         m_eta = DilithiumEta::Eta2;
         m_tau = 60;
         m_beta = 120;
         m_gamma1 = (1 << 19);
         m_gamma2 = ((DilithiumModeConstants::Q - 1) / 32);
         m_omega = 75;
         m_nist_security_strength = 5;
         m_polyz_packedbytes = 640;
         m_polyw1_packedbytes = 128;
         m_polyeta_packedbytes = 96;
         m_poly_uniform_eta_nblocks = ((136 + m_stream128_blockbytes - 1) / m_stream128_blockbytes);
         break;
      }

   if(m_gamma1 == (1 << 17))
      {
      m_poly_uniform_gamma1_nblocks = (576 + m_stream256_blockbytes - 1) / m_stream256_blockbytes;
      }
   else
      {
      BOTAN_ASSERT_NOMSG(m_gamma1 == (1 << 19));
      m_poly_uniform_gamma1_nblocks = (640 + m_stream256_blockbytes - 1) / m_stream256_blockbytes;
      }

   // For all modes the same calculation
   m_polyvech_packedbytes = m_omega + m_k;
   m_poly_uniform_nblocks = ((768 + m_stream128_blockbytes - 1) / m_stream128_blockbytes);
   m_public_key_bytes = DilithiumModeConstants::SEEDBYTES + m_k * DilithiumModeConstants::POLYT1_PACKEDBYTES;
   m_crypto_bytes = DilithiumModeConstants::SEEDBYTES + m_l * m_polyz_packedbytes + m_polyvech_packedbytes;
   m_private_key_bytes = (3 * DilithiumModeConstants::SEEDBYTES + m_l * m_polyeta_packedbytes \
                          + m_k * m_polyeta_packedbytes + m_k * DilithiumModeConstants::POLYT0_PACKEDBYTES);
   }


}  // namespace Botan
