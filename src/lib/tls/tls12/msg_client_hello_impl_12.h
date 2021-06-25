/*
* TLS Messages
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CLIENT_HELLO_IMPL_12_H_
#define BOTAN_TLS_CLIENT_HELLO_IMPL_12_H_

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/tls_handshake_msg.h>
#include <botan/tls_session.h>
#include <botan/tls_policy.h>
#include <botan/tls_ciphersuite.h>
#include <botan/pk_keys.h>
#include <botan/x509cert.h>
#include <botan/ocsp.h>
#include <vector>
#include <string>
#include <set>

#if defined(BOTAN_HAS_CECPQ1)
  #include <botan/cecpq1.h>
#endif

namespace Botan {
namespace TLS {

class Session;
class Handshake_IO;
class Handshake_State;
class Callbacks;

std::vector<uint8_t> make_hello_random(RandomNumberGenerator& rng,
                                       const Policy& policy);
/**
* Client Hello Message
*/
class BOTAN_UNSTABLE_API Client_Hello_Impl_12 final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override;

      Protocol_Version version() const;

      std::vector<Protocol_Version> supported_versions() const;

      const std::vector<uint8_t>& random() const;

      const std::vector<uint8_t>& session_id() const;

      const std::vector<uint8_t>& compression_methods() const;

      const std::vector<uint16_t>& ciphersuites() const;

      bool offered_suite(uint16_t ciphersuite) const;

      bool sent_fallback_scsv() const;

      std::vector<Signature_Scheme> signature_schemes() const;

      std::vector<Group_Params> supported_ecc_curves() const;

      std::vector<Group_Params> supported_dh_groups() const;

      bool prefers_compressed_ec_points() const;

      std::string sni_hostname() const;

      bool secure_renegotiation() const;

      std::vector<uint8_t> renegotiation_info() const;

      bool supports_session_ticket() const;

      std::vector<uint8_t> session_ticket() const;

      bool supports_alpn() const;

      bool supports_extended_master_secret() const;

      bool supports_cert_status_message() const;

      bool supports_encrypt_then_mac() const;

      bool sent_signature_algorithms() const;

      std::vector<std::string> next_protocols() const;

      std::vector<uint16_t> srtp_profiles() const;

      void update_hello_cookie(const Hello_Verify_Request& hello_verify);

      const std::vector<uint8_t>& cookie() const;

      std::vector<uint8_t> cookie_input_data() const;

      std::set<Handshake_Extension_Type> extension_types() const;

      const Extensions& extensions() const;

      Client_Hello_Impl_12(Handshake_IO& io,
                   Handshake_Hash& hash,
                   const Policy& policy,
                   Callbacks& cb,
                   RandomNumberGenerator& rng,
                   const std::vector<uint8_t>& reneg_info,
                   const Client_Hello::Settings& client_settings,
                   const std::vector<std::string>& next_protocols);

      Client_Hello_Impl_12(Handshake_IO& io,
                   Handshake_Hash& hash,
                   const Policy& policy,
                   Callbacks& cb,
                   RandomNumberGenerator& rng,
                   const std::vector<uint8_t>& reneg_info,
                   const Session& resumed_session,
                   const std::vector<std::string>& next_protocols);

      explicit Client_Hello_Impl_12(const std::vector<uint8_t>& buf);

   private:
      std::vector<uint8_t> serialize() const override;

      Protocol_Version m_version;
      std::vector<uint8_t> m_session_id;
      std::vector<uint8_t> m_random;
      std::vector<uint16_t> m_suites;
      std::vector<uint8_t> m_comp_methods;
      std::vector<uint8_t> m_hello_cookie; // DTLS only
      std::vector<uint8_t> m_cookie_input_bits; // DTLS only

      Extensions m_extensions;
   };

}

}

#endif
