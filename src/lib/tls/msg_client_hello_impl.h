/*
* TLS Messages
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_CLIENT_HELLO_IMPL_H_
#define BOTAN_MSG_CLIENT_HELLO_IMPL_H_

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

/**
* Client Hello Message Impl
*/
class Client_Hello_Impl : public Handshake_Message
   {
   public:
      Client_Hello_Impl();

      explicit Client_Hello_Impl(const Policy& policy,
                        RandomNumberGenerator& rng,
                        const Client_Hello::Settings& client_settings);

      explicit Client_Hello_Impl(const Policy& policy,
                           RandomNumberGenerator& rng,
                           const Session& session);

      virtual ~Client_Hello_Impl();

      Handshake_Type type() const override;

      virtual Protocol_Version version() const = 0;

      virtual std::vector<Protocol_Version> supported_versions() const = 0;

      virtual const std::vector<uint8_t>& random() const = 0;

      virtual const std::vector<uint8_t>& session_id() const = 0;

      virtual const std::vector<uint8_t>& compression_methods() const = 0;

      virtual const std::vector<uint16_t>& ciphersuites() const = 0;

      virtual bool offered_suite(uint16_t ciphersuite) const = 0;

      virtual std::vector<Signature_Scheme> signature_schemes() const = 0;

      virtual std::vector<Group_Params> supported_ecc_curves() const = 0;

      virtual std::vector<Group_Params> supported_dh_groups() const = 0;

      virtual bool prefers_compressed_ec_points() const = 0;

      virtual std::string sni_hostname() const = 0;

      virtual bool secure_renegotiation() const = 0;

      virtual std::vector<uint8_t> renegotiation_info() const = 0;

      virtual bool supports_session_ticket() const = 0;

      virtual std::vector<uint8_t> session_ticket() const = 0;

      virtual bool supports_alpn() const = 0;

      virtual bool supports_extended_master_secret() const = 0;

      virtual bool supports_cert_status_message() const = 0;

      virtual bool supports_encrypt_then_mac() const = 0;

      virtual bool sent_signature_algorithms() const = 0;

      virtual std::vector<std::string> next_protocols() const = 0;

      virtual std::vector<uint16_t> srtp_profiles() const = 0;

      virtual void update_hello_cookie(const Hello_Verify_Request& hello_verify) = 0;

      virtual const std::vector<uint8_t>& cookie() const = 0;

      virtual std::vector<uint8_t> cookie_input_data() const = 0;

      virtual std::set<Handshake_Extension_Type> extension_types() const = 0;

      virtual const Extensions& extensions() const = 0;

   protected:
      Protocol_Version m_version;
      std::vector<uint8_t> m_session_id;
      std::vector<uint8_t> m_random;
      std::vector<uint16_t> m_suites;
      std::vector<uint8_t> m_comp_methods;
      Extensions m_extensions;
   };

}

}

#endif
