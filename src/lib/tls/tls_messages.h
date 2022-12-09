/*
* TLS Messages
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_MESSAGES_H_
#define BOTAN_TLS_MESSAGES_H_

#include <vector>
#include <string>
#include <set>
#include <memory>
#include <optional>
#include <variant>

#include <botan/tls_extensions.h>
#include <botan/tls_handshake_msg.h>
#include <botan/tls_session.h>
#include <botan/tls_policy.h>
#include <botan/tls_ciphersuite.h>
#include <botan/pk_keys.h>
#include <botan/x509cert.h>

namespace Botan {

class Public_Key;
class Credentials_Manager;

namespace OCSP {
class Response;
}

namespace TLS {

class Session;
class Handshake_IO;
class Handshake_State;
class Hello_Retry_Request;
class Callbacks;
class Cipher_State;

std::vector<uint8_t> make_hello_random(RandomNumberGenerator& rng,
                                       Callbacks& cb,
                                       const Policy& policy);

/**
* DTLS Hello Verify Request
*/
class BOTAN_UNSTABLE_API Hello_Verify_Request final : public Handshake_Message
   {
   public:
      std::vector<uint8_t> serialize() const override;
      Handshake_Type type() const override { return HELLO_VERIFY_REQUEST; }

      const std::vector<uint8_t>& cookie() const { return m_cookie; }

      explicit Hello_Verify_Request(const std::vector<uint8_t>& buf);

      Hello_Verify_Request(const std::vector<uint8_t>& client_hello_bits,
                           const std::string& client_identity,
                           const SymmetricKey& secret_key);

   private:
      std::vector<uint8_t> m_cookie;
   };

class Client_Hello_Internal;

/**
* Client Hello Message
*/
class BOTAN_UNSTABLE_API Client_Hello : public Handshake_Message
   {
   public:
      Client_Hello(const Client_Hello&) = delete;
      Client_Hello& operator=(const Client_Hello&) = delete;
      Client_Hello(Client_Hello&&);
      Client_Hello& operator=(Client_Hello&&);

      ~Client_Hello();

      Handshake_Type type() const override;

      /**
       * Return the version indicated in the ClientHello.
       * This may differ from the version indicated in the supported_versions extension.
       *
       * See RFC 8446 4.1.2:
       *   TLS 1.3, the client indicates its version preferences in the
       *   "supported_versions" extension (Section 4.2.1) and the
       *   legacy_version field MUST be set to 0x0303, which is the version
       *   number for TLS 1.2.
       */
      Protocol_Version legacy_version() const;

      const std::vector<uint8_t>& random() const;

      const std::vector<uint8_t>& session_id() const;

      const std::vector<uint16_t>& ciphersuites() const;

      bool offered_suite(uint16_t ciphersuite) const;

      std::vector<Signature_Scheme> signature_schemes() const;

      std::vector<Group_Params> supported_ecc_curves() const;

      std::vector<Group_Params> supported_dh_groups() const;

      std::vector<Protocol_Version> supported_versions() const;

      std::string sni_hostname() const;

      bool supports_alpn() const;

      bool sent_signature_algorithms() const;

      std::vector<std::string> next_protocols() const;

      std::vector<uint16_t> srtp_profiles() const;

      std::vector<uint8_t> serialize() const override;


      const std::vector<uint8_t>& cookie() const;

      std::vector<uint8_t> cookie_input_data() const;

      std::set<Handshake_Extension_Type> extension_types() const;

      const Extensions& extensions() const;

   protected:
      Client_Hello();
      explicit Client_Hello(std::unique_ptr<Client_Hello_Internal> data);

      const std::vector<uint8_t>& compression_methods() const;

   protected:
      std::unique_ptr<Client_Hello_Internal> m_data;
   };

class BOTAN_UNSTABLE_API Client_Hello_12 final : public Client_Hello
   {
   public:
      class Settings final
         {
         public:
            Settings(const Protocol_Version version,
                     const std::string& hostname = ""):
               m_new_session_version(version),
               m_hostname(hostname) {}

            const Protocol_Version protocol_version() const { return m_new_session_version; }
            const std::string& hostname() const { return m_hostname; }

         private:
            const Protocol_Version m_new_session_version;
            const std::string m_hostname;
         };

   public:
      explicit Client_Hello_12(const std::vector<uint8_t>& buf);

      Client_Hello_12(Handshake_IO& io,
                      Handshake_Hash& hash,
                      const Policy& policy,
                      Callbacks& cb,
                      RandomNumberGenerator& rng,
                      const std::vector<uint8_t>& reneg_info,
                      const Settings& client_settings,
                      const std::vector<std::string>& next_protocols);

      Client_Hello_12(Handshake_IO& io,
                      Handshake_Hash& hash,
                      const Policy& policy,
                      Callbacks& cb,
                      RandomNumberGenerator& rng,
                      const std::vector<uint8_t>& reneg_info,
                      const Session& session,
                      const std::vector<std::string>& next_protocols);

   protected:
      friend class Client_Hello_13;  // to allow construction by Client_Hello_13::parse()
      Client_Hello_12(std::unique_ptr<Client_Hello_Internal> data);

   public:
      using Client_Hello::random;
      using Client_Hello::compression_methods;

      bool prefers_compressed_ec_points() const;

      bool secure_renegotiation() const;

      std::vector<uint8_t> renegotiation_info() const;

      bool supports_session_ticket() const;

      std::vector<uint8_t> session_ticket() const;

      bool supports_extended_master_secret() const;

      bool supports_cert_status_message() const;

      bool supports_encrypt_then_mac() const;

      void update_hello_cookie(const Hello_Verify_Request& hello_verify);
   };

#if defined(BOTAN_HAS_TLS_13)

class BOTAN_UNSTABLE_API Client_Hello_13 final : public Client_Hello
   {
   public:
      Client_Hello_13(const Policy& policy,
                      Callbacks& cb,
                      RandomNumberGenerator& rng,
                      const std::string& hostname,
                      const std::vector<std::string>& next_protocols,
                      const std::optional<Session>& session = std::nullopt);

      static std::variant<Client_Hello_13, Client_Hello_12>
      parse(const std::vector<uint8_t>& buf);

      void retry(const Hello_Retry_Request& hrr,
                 const Transcript_Hash_State& transcript_hash_state,
                 Callbacks& cb,
                 RandomNumberGenerator& rng);

      /**
       * Select the highest protocol version from the list of versions
       * supported by the client. If no such version can be determind this
       * returns std::nullopt.
       */
      std::optional<Protocol_Version> highest_supported_version(const Policy& policy) const;

      /**
       * This validates that a Client Hello received after sending a Hello
       * Retry Request was updated in accordance with RFC 8446 4.1.2. If issues
       * are found, this method throws accordingly.
       */
      void validate_updates(const Client_Hello_13& new_ch);

   private:
      Client_Hello_13(std::unique_ptr<Client_Hello_Internal> data);

      /**
       * If the Client Hello contains a PSK extensions with identities this will
       * generate the PSK binders as described in RFC 8446 4.2.11.2.
       * Note that the passed in \p transcript_hash_state might be virgin for
       * the initial Client Hello and should be primed with ClientHello1 and
       * HelloRetryRequest for an updated Client Hello.
       */
      void calculate_psk_binders(Transcript_Hash_State transcript_hash_state);
   };

#endif // BOTAN_HAS_TLS_13

class Server_Hello_Internal;

/**
* Server Hello Message
*/
class BOTAN_UNSTABLE_API Server_Hello : public Handshake_Message
   {
   public:
      Server_Hello(const Server_Hello&) = delete;
      Server_Hello& operator=(const Server_Hello&) = delete;
      Server_Hello(Server_Hello&&);
      Server_Hello& operator=(Server_Hello&&);

      ~Server_Hello();

      std::vector<uint8_t> serialize() const override;

      Handshake_Type type() const override;

      // methods available in both subclasses' interface
      uint16_t ciphersuite() const;
      const Extensions& extensions() const;
      const std::vector<uint8_t>& session_id() const;

      virtual Protocol_Version selected_version() const = 0;

   protected:
      explicit Server_Hello(std::unique_ptr<Server_Hello_Internal> data);

      // methods used internally and potentially exposed by one of the subclasses
      std::set<Handshake_Extension_Type> extension_types() const;
      const std::vector<uint8_t>& random() const;
      uint8_t compression_method() const;
      Protocol_Version legacy_version() const;

   protected:
      std::unique_ptr<Server_Hello_Internal> m_data;
   };

class BOTAN_UNSTABLE_API Server_Hello_12 final : public Server_Hello
   {
   public:
      class Settings final
         {
         public:
            Settings(const std::vector<uint8_t> new_session_id,
                     Protocol_Version new_session_version,
                     uint16_t ciphersuite,
                     bool offer_session_ticket) :
               m_new_session_id(new_session_id),
               m_new_session_version(new_session_version),
               m_ciphersuite(ciphersuite),
               m_offer_session_ticket(offer_session_ticket) {}

            const std::vector<uint8_t>& session_id() const { return m_new_session_id; }
            Protocol_Version protocol_version() const { return m_new_session_version; }
            uint16_t ciphersuite() const { return m_ciphersuite; }
            bool offer_session_ticket() const { return m_offer_session_ticket; }

         private:
            const std::vector<uint8_t> m_new_session_id;
            Protocol_Version m_new_session_version;
            uint16_t m_ciphersuite;
            bool m_offer_session_ticket;
         };

      Server_Hello_12(Handshake_IO& io,
                      Handshake_Hash& hash,
                      const Policy& policy,
                      Callbacks& cb,
                      RandomNumberGenerator& rng,
                      const std::vector<uint8_t>& secure_reneg_info,
                      const Client_Hello_12& client_hello,
                      const Settings& settings,
                      const std::string& next_protocol);

      Server_Hello_12(Handshake_IO& io,
                      Handshake_Hash& hash,
                      const Policy& policy,
                      Callbacks& cb,
                      RandomNumberGenerator& rng,
                      const std::vector<uint8_t>& secure_reneg_info,
                      const Client_Hello_12& client_hello,
                      Session& resumed_session,
                      bool offer_session_ticket,
                      const std::string& next_protocol);

      explicit Server_Hello_12(const std::vector<uint8_t> &buf);

   protected:
      friend class Server_Hello_13;  // to allow construction by Server_Hello_13::parse()
      explicit Server_Hello_12(std::unique_ptr<Server_Hello_Internal> data);

   public:
      using Server_Hello::random;
      using Server_Hello::compression_method;
      using Server_Hello::extension_types;
      using Server_Hello::legacy_version;

      /**
       * @returns the selected version as indicated in the legacy_version field
       */
      Protocol_Version selected_version() const override;

      bool secure_renegotiation() const;

      std::vector<uint8_t> renegotiation_info() const;

      std::string next_protocol() const;

      bool supports_extended_master_secret() const;

      bool supports_encrypt_then_mac() const;

      bool supports_certificate_status_message() const;

      bool supports_session_ticket() const;

      uint16_t srtp_profile() const;
      bool prefers_compressed_ec_points() const;

      /**
       * Return desired downgrade version indicated by hello random, if any.
       */
      std::optional<Protocol_Version> random_signals_downgrade() const;
   };

#if defined(BOTAN_HAS_TLS_13)

class Hello_Retry_Request;

class BOTAN_UNSTABLE_API Server_Hello_13 : public Server_Hello
   {
   protected:
      static struct Server_Hello_Tag {} as_server_hello;
      static struct Hello_Retry_Request_Tag {} as_hello_retry_request;
      static struct Hello_Retry_Request_Creation_Tag {} as_new_hello_retry_request;

      // These constructors are meant for instantiating Server Hellos
      // after parsing a peer's message. They perform basic validation
      // and are therefore not suitable for constructing a message to
      // be sent to a client.
      explicit Server_Hello_13(std::unique_ptr<Server_Hello_Internal> data, Server_Hello_Tag tag = as_server_hello);
      explicit Server_Hello_13(std::unique_ptr<Server_Hello_Internal> data, Hello_Retry_Request_Tag tag);
      void basic_validation() const;

      // Instantiate a Server Hello as response to a client's Client Hello
      // (called from Server_Hello_13::create())
      Server_Hello_13(const Client_Hello_13& ch, std::optional<Named_Group> key_exchange_group, RandomNumberGenerator& rng, Callbacks& cb, const Policy& policy);

      explicit Server_Hello_13(std::unique_ptr<Server_Hello_Internal> data, Hello_Retry_Request_Creation_Tag tag);

   public:
      static std::variant<Hello_Retry_Request, Server_Hello_13>
      create(const Client_Hello_13& ch, bool hello_retry_request_allowed, RandomNumberGenerator& rng, const Policy& policy, Callbacks& cb);

      static std::variant<Hello_Retry_Request, Server_Hello_13, Server_Hello_12>
      parse(const std::vector<uint8_t>& buf);

      /**
       * Return desired downgrade version indicated by hello random, if any.
       */
      std::optional<Protocol_Version> random_signals_downgrade() const;

      /**
       * @returns the selected version as indicated by the supported_versions extension
       */
      Protocol_Version selected_version() const override;
   };

class BOTAN_UNSTABLE_API Hello_Retry_Request final : public Server_Hello_13
   {
   protected:
      friend class Server_Hello_13;  // to allow construction by Server_Hello_13::parse() and ::create()
      explicit Hello_Retry_Request(std::unique_ptr<Server_Hello_Internal> data);
      Hello_Retry_Request(const Client_Hello_13& ch, Named_Group selected_group, const Policy& policy, Callbacks& cb);

   public:
      Handshake_Type type() const override { return HELLO_RETRY_REQUEST; }
      Handshake_Type wire_type() const override { return SERVER_HELLO; }
   };

#endif // BOTAN_HAS_TLS_13

class BOTAN_UNSTABLE_API Encrypted_Extensions final : public Handshake_Message
   {
   public:
      explicit Encrypted_Extensions(const std::vector<uint8_t>& buf);
      Encrypted_Extensions(const Client_Hello_13& client_hello, const Policy& policy, Callbacks& cb);

      Handshake_Type type() const override { return Handshake_Type::ENCRYPTED_EXTENSIONS; }

      const Extensions& extensions() const { return m_extensions; }

      std::vector<uint8_t> serialize() const override;

   private:
      Extensions m_extensions;
   };

/**
* Client Key Exchange Message
*/
class BOTAN_UNSTABLE_API Client_Key_Exchange final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return CLIENT_KEX; }

      const secure_vector<uint8_t>& pre_master_secret() const
         { return m_pre_master; }

      Client_Key_Exchange(Handshake_IO& io,
                          Handshake_State& state,
                          const Policy& policy,
                          Credentials_Manager& creds,
                          const Public_Key* server_public_key,
                          const std::string& hostname,
                          RandomNumberGenerator& rng);

      Client_Key_Exchange(const std::vector<uint8_t>& buf,
                          const Handshake_State& state,
                          const Private_Key* server_rsa_kex_key,
                          Credentials_Manager& creds,
                          const Policy& policy,
                          RandomNumberGenerator& rng);

   private:
      std::vector<uint8_t> serialize() const override
         { return m_key_material; }

      std::vector<uint8_t> m_key_material;
      secure_vector<uint8_t> m_pre_master;
   };

/**
* Certificate Message of TLS 1.2
*/
class BOTAN_UNSTABLE_API Certificate_12 final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return CERTIFICATE; }
      const std::vector<X509_Certificate>& cert_chain() const { return m_certs; }

      size_t count() const { return m_certs.size(); }
      bool empty() const { return m_certs.empty(); }

      Certificate_12(Handshake_IO& io,
                     Handshake_Hash& hash,
                     const std::vector<X509_Certificate>& certs);

      Certificate_12(const std::vector<uint8_t>& buf, const Policy& policy);

      std::vector<uint8_t> serialize() const override;

   private:
      std::vector<X509_Certificate> m_certs;
   };

class Certificate_Request_13;

/**
* Certificate Message of TLS 1.3
*/
class BOTAN_UNSTABLE_API Certificate_13 final : public Handshake_Message
   {
   public:
      struct Certificate_Entry
         {
         // TODO: RFC 8446 4.4.2 specifies the possibility to negotiate the usage
         //       of a single raw public key in lieu of the X.509 certificate
         //       chain. This is left for future work.
         X509_Certificate certificate;
         Extensions       extensions;
         };

   public:
      Handshake_Type type() const override { return CERTIFICATE; }
      std::vector<X509_Certificate> cert_chain() const;

      size_t count() const { return m_entries.size(); }
      bool empty() const { return m_entries.empty(); }
      const X509_Certificate& leaf() const;
      const std::vector<uint8_t>& request_context() const { return m_request_context; }

      /**
       * Create a Client Certificate message
       * ... in response to a Certificate Request message.
       */
      Certificate_13(const Certificate_Request_13& cert_request,
                     const std::string& hostname,
                     Credentials_Manager& credentials_manager,
                     Callbacks& callbacks);

      /**
       * Create a Server Certificate message
       * ... in response to a Client Hello indicating the need to authenticate
       *     with a server certificate.
       */
      Certificate_13(const Client_Hello_13& client_hello,
                     Credentials_Manager& credentials_manager,
                     Callbacks& callbacks);

      /**
      * Deserialize a Certificate message
      * @param buf the serialized message
      * @param policy the TLS policy
      * @param side is this a SERVER or CLIENT certificate message
      */
      Certificate_13(const std::vector<uint8_t>& buf,
                     const Policy& policy,
                     const Connection_Side side);

      /**
      * Validate a Certificate message regarding what extensions are expected based on
      * previous handshake messages. Also call the tls_examine_extenions() callback
      * for each entry.
      *
      * @param requested_extensions Extensions of Client_Hello or Certificate_Request messages
      */
      void validate_extensions(const std::set<Handshake_Extension_Type>& requested_extensions, Callbacks& cb) const;

      /**
       * Verify the certificate chain
       *
       * @throws if verification fails.
       */
      void verify(Callbacks& callbacks,
                  const Policy& policy,
                  Credentials_Manager& creds,
                  const std::string& hostname,
                  bool use_ocsp) const;

      std::vector<uint8_t> serialize() const override;

   private:
      void setup_entries(std::vector<X509_Certificate> cert_chain,
                         Callbacks& callbacks);

   private:
      std::vector<uint8_t>           m_request_context;
      std::vector<Certificate_Entry> m_entries;
      Connection_Side                m_side;
   };

/**
* Certificate Status (RFC 6066)
*/
class BOTAN_UNSTABLE_API Certificate_Status final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return CERTIFICATE_STATUS; }

      //std::shared_ptr<const OCSP::Response> response() const { return m_response; }

      const std::vector<uint8_t>& response() const { return m_response; }

      explicit Certificate_Status(const std::vector<uint8_t>& buf);

      Certificate_Status(Handshake_IO& io,
                         Handshake_Hash& hash,
                         const OCSP::Response& response);

      /*
       * Create a Certificate_Status message using an already DER encoded OCSP response.
       */
      Certificate_Status(Handshake_IO& io,
                         Handshake_Hash& hash,
                         const std::vector<uint8_t>& raw_response_bytes);

   private:
      std::vector<uint8_t> serialize() const override;
      std::vector<uint8_t> m_response;
   };

/**
* Certificate Request Message (TLS 1.2)
*/
class BOTAN_UNSTABLE_API Certificate_Request_12 final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override;

      const std::vector<std::string>& acceptable_cert_types() const;

      const std::vector<X509_DN>& acceptable_CAs() const;

      const std::vector<Signature_Scheme>& signature_schemes() const;

      Certificate_Request_12(Handshake_IO& io,
                      Handshake_Hash& hash,
                      const Policy& policy,
                      const std::vector<X509_DN>& allowed_cas);

      explicit Certificate_Request_12(const std::vector<uint8_t>& buf);

      std::vector<uint8_t> serialize() const override;

   private:
      std::vector<X509_DN> m_names;
      std::vector<std::string> m_cert_key_types;
      std::vector<Signature_Scheme> m_schemes;
   };

#if defined(BOTAN_HAS_TLS_13)

class BOTAN_UNSTABLE_API Certificate_Request_13 final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override;

      Certificate_Request_13(const std::vector<uint8_t>& buf, const Connection_Side side);

      std::vector<X509_DN> acceptable_CAs() const;
      const std::vector<Signature_Scheme>& signature_schemes() const;
      const Extensions& extensions() const { return m_extensions; }

      std::vector<uint8_t> serialize() const override;

      const std::vector<uint8_t> context() const { return m_context; }

   private:
      std::vector<uint8_t> m_context;
      Extensions m_extensions;
   };

#endif

class BOTAN_UNSTABLE_API Certificate_Verify : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return CERTIFICATE_VERIFY; }

      Signature_Scheme signature_scheme() const { return m_scheme; }

      Certificate_Verify(const std::vector<uint8_t>& buf);
      Certificate_Verify() = default;

      std::vector<uint8_t> serialize() const override;

   protected:
      std::vector<uint8_t> m_signature;
      Signature_Scheme m_scheme;
   };

/**
* Certificate Verify Message
*/
class BOTAN_UNSTABLE_API Certificate_Verify_12 final : public Certificate_Verify
   {
   public:
      using Certificate_Verify::Certificate_Verify;

      Certificate_Verify_12(Handshake_IO& io,
                            Handshake_State& state,
                            const Policy& policy,
                            RandomNumberGenerator& rng,
                            const Private_Key* key);

      /**
      * Check the signature on a certificate verify message
      * @param cert the purported certificate
      * @param state the handshake state
      * @param policy the TLS policy
      */
      bool verify(const X509_Certificate& cert,
                  const Handshake_State& state,
                  const Policy& policy) const;
   };

#if defined(BOTAN_HAS_TLS_13)

/**
* Certificate Verify Message
*/
class BOTAN_UNSTABLE_API Certificate_Verify_13 final : public Certificate_Verify
   {
   public:
      /**
      * Deserialize a Certificate message
      * @param buf the serialized message
      * @param side is this a SERVER or CLIENT certificate message
      */
      Certificate_Verify_13(const std::vector<uint8_t>& buf,
                            const Connection_Side side);

      Certificate_Verify_13(
            const Certificate_13& certificate_message,
            const std::vector<Signature_Scheme>& peer_allowed_schemes,
            const std::string& hostname,
            const Transcript_Hash& hash,
            Connection_Side whoami,
            Credentials_Manager& creds_mgr,
            const Policy& policy,
            Callbacks& callbacks,
            RandomNumberGenerator& rng);

      bool verify(const X509_Certificate& cert,
                  Callbacks& callbacks,
                  const Transcript_Hash& transcript_hash) const;

   private:
      Connection_Side m_side;
   };

#endif

/**
* Finished Message
*/
class BOTAN_UNSTABLE_API Finished : public Handshake_Message
   {
   public:
      explicit Finished(const std::vector<uint8_t>& buf);

      Handshake_Type type() const override { return FINISHED; }

      std::vector<uint8_t> verify_data() const;

      std::vector<uint8_t> serialize() const override;

   protected:
      using Handshake_Message::Handshake_Message;
      std::vector<uint8_t> m_verification_data;
   };

class BOTAN_UNSTABLE_API Finished_12 final : public Finished
   {
   public:
      using Finished::Finished;
      Finished_12(Handshake_IO& io,
                  Handshake_State& state,
                  Connection_Side side);

      bool verify(const Handshake_State& state, Connection_Side side) const;
   };

#if defined(BOTAN_HAS_TLS_13)
class BOTAN_UNSTABLE_API Finished_13 final : public Finished
   {
   public:
      using Finished::Finished;
      Finished_13(Cipher_State* cipher_state,
                  const Transcript_Hash& transcript_hash);

      bool verify(Cipher_State* cipher_state,
                  const Transcript_Hash& transcript_hash) const;
   };
#endif

/**
* Hello Request Message
*/
class BOTAN_UNSTABLE_API Hello_Request final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return HELLO_REQUEST; }

      explicit Hello_Request(Handshake_IO& io);
      explicit Hello_Request(const std::vector<uint8_t>& buf);

   private:
      std::vector<uint8_t> serialize() const override;
   };

/**
* Server Key Exchange Message
*/
class BOTAN_UNSTABLE_API Server_Key_Exchange final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return SERVER_KEX; }

      const std::vector<uint8_t>& params() const { return m_params; }

      bool verify(const Public_Key& server_key,
                  const Handshake_State& state,
                  const Policy& policy) const;

      // Only valid for certain kex types
      const Private_Key& server_kex_key() const;

      Server_Key_Exchange(Handshake_IO& io,
                          Handshake_State& state,
                          const Policy& policy,
                          Credentials_Manager& creds,
                          RandomNumberGenerator& rng,
                          const Private_Key* signing_key = nullptr);

      Server_Key_Exchange(const std::vector<uint8_t>& buf,
                          Kex_Algo kex_alg,
                          Auth_Method sig_alg,
                          Protocol_Version version);

   private:
      std::vector<uint8_t> serialize() const override;

      std::unique_ptr<Private_Key> m_kex_key;

      std::vector<uint8_t> m_params;

      std::vector<uint8_t> m_signature;
      Signature_Scheme m_scheme;
   };

/**
* Server Hello Done Message
*/
class BOTAN_UNSTABLE_API Server_Hello_Done final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return SERVER_HELLO_DONE; }

      explicit Server_Hello_Done(Handshake_IO& io, Handshake_Hash& hash);
      explicit Server_Hello_Done(const std::vector<uint8_t>& buf);

   private:
      std::vector<uint8_t> serialize() const override;
   };

/**
* New Session Ticket Message
*/
class BOTAN_UNSTABLE_API New_Session_Ticket_12 final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return NEW_SESSION_TICKET; }

      uint32_t ticket_lifetime_hint() const { return m_ticket_lifetime_hint; }
      const std::vector<uint8_t>& ticket() const { return m_ticket; }

      New_Session_Ticket_12(Handshake_IO& io,
                            Handshake_Hash& hash,
                            const std::vector<uint8_t>& ticket,
                            uint32_t lifetime);

      New_Session_Ticket_12(Handshake_IO& io,
                            Handshake_Hash& hash);

      explicit New_Session_Ticket_12(const std::vector<uint8_t>& buf);

      std::vector<uint8_t> serialize() const override;

   private:
      uint32_t m_ticket_lifetime_hint = 0;
      std::vector<uint8_t> m_ticket;
   };

#if defined(BOTAN_HAS_TLS_13)

class BOTAN_UNSTABLE_API New_Session_Ticket_13 final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return NEW_SESSION_TICKET; }

      New_Session_Ticket_13(const std::vector<uint8_t>& buf,
                            Connection_Side from);

      std::vector<uint8_t> serialize() const override;

      const Extensions& extensions() const { return m_extensions; }

      const std::vector<uint8_t>& ticket() const { return m_ticket; }
      const std::vector<uint8_t>& nonce() const { return m_ticket_nonce; }
      uint32_t ticket_age_add() const { return m_ticket_age_add; }
      uint32_t lifetime_hint() const { return m_ticket_lifetime_hint; }

      /**
       * @return  the number of bytes allowed for early data or std::nullopt
       *          when early data is not allowed at all
       */
      std::optional<uint32_t> early_data_byte_limit() const;

   private:
      // RFC 8446 4.6.1
      //    Clients MUST NOT cache tickets for longer than 7 days, regardless of
      //    the ticket_lifetime, and MAY delete tickets earlier based on local
      //    policy.  A server MAY treat a ticket as valid for a shorter period
      //    of time than what is stated in the ticket_lifetime.
      //
      // ... hence we call it 'lifetime hint'.
      uint32_t m_ticket_lifetime_hint;
      uint32_t m_ticket_age_add;
      std::vector<uint8_t> m_ticket_nonce;
      std::vector<uint8_t> m_ticket;
      Extensions m_extensions;
   };

#endif

/**
* Change Cipher Spec
*/
class BOTAN_UNSTABLE_API Change_Cipher_Spec final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return HANDSHAKE_CCS; }

      std::vector<uint8_t> serialize() const override
         { return std::vector<uint8_t>(1, 1); }
   };

class BOTAN_UNSTABLE_API Key_Update final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return  KEY_UPDATE; }

      explicit Key_Update(const bool request_peer_update);
      explicit Key_Update(const std::vector<uint8_t>& buf);

      std::vector<uint8_t> serialize() const override;

      bool expects_reciprocation() const { return m_update_requested; }

   private:
      bool m_update_requested;
   };

#if defined(BOTAN_HAS_TLS_13)

namespace {
template <typename T>
struct as_wrapped_references
   {
   };

template <typename... AlternativeTs>
struct as_wrapped_references<std::variant<AlternativeTs...>>
   {
   using type = std::variant<std::reference_wrapper<AlternativeTs>...>;
   };

template <typename T>
using as_wrapped_references_t = typename as_wrapped_references<T>::type;
}

// Handshake message types from RFC 8446 4.
using Handshake_Message_13 = std::variant<
                             Client_Hello_13,
                             Client_Hello_12,
                             Server_Hello_13,
                             Server_Hello_12,
                             Hello_Retry_Request,
                             // End_Of_Early_Data,
                             Encrypted_Extensions,
                             Certificate_13,
                             Certificate_Request_13,
                             Certificate_Verify_13,
                             Finished_13>;
using Handshake_Message_13_Ref = as_wrapped_references_t<Handshake_Message_13>;

using Post_Handshake_Message_13 = std::variant<
                                  New_Session_Ticket_13,
                                  Key_Update>;

using Server_Handshake_13_Message = std::variant<
                                    Server_Hello_13,
                                    Server_Hello_12,  // indicates a TLS version downgrade
                                    Hello_Retry_Request,
                                    Encrypted_Extensions,
                                    Certificate_13,
                                    Certificate_Request_13,
                                    Certificate_Verify_13,
                                    Finished_13>;
using Server_Handshake_13_Message_Ref = as_wrapped_references_t<Server_Handshake_13_Message>;

using Client_Handshake_13_Message = std::variant<
                                    Client_Hello_13,
                                    Client_Hello_12,  // indicates a TLS peer that does not offer TLS 1.3
                                    Certificate_13,
                                    Certificate_Verify_13,
                                    Finished_13>;
using Client_Handshake_13_Message_Ref = as_wrapped_references_t<Client_Handshake_13_Message>;

#endif // BOTAN_HAS_TLS_13

}

}

#endif
