/*
* TLS Client Hello Message - implementation for TLS 1.2
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_CLIENT_HELLO_IMPL_12_H_
#define BOTAN_MSG_CLIENT_HELLO_IMPL_12_H_

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/tls_handshake_msg.h>
#include <botan/internal/msg_client_hello_impl.h>
#include <vector>
#include <string>

namespace Botan {
namespace TLS {

class Session;
class Handshake_IO;
class Policy;
class Callbacks;

std::vector<uint8_t> make_hello_random(RandomNumberGenerator& rng,
                                       const Policy& policy);
/**
* Client Hello Message TLSv1.2 implementation
*/
class Client_Hello_Impl_12 final : public Client_Hello_Impl
   {
   public:
      explicit Client_Hello_Impl_12(Handshake_IO& io,
                                    Handshake_Hash& hash,
                                    const Policy& policy,
                                    Callbacks& cb,
                                    RandomNumberGenerator& rng,
                                    const std::vector<uint8_t>& reneg_info,
                                    const Client_Hello::Settings& client_settings,
                                    const std::vector<std::string>& next_protocols);

      explicit Client_Hello_Impl_12(Handshake_IO& io,
                                    Handshake_Hash& hash,
                                    const Policy& policy,
                                    Callbacks& cb,
                                    RandomNumberGenerator& rng,
                                    const std::vector<uint8_t>& reneg_info,
                                    const Session& resumed_session,
                                    const std::vector<std::string>& next_protocols);

      explicit Client_Hello_Impl_12(const std::vector<uint8_t>& buf);

      std::vector<Protocol_Version> supported_versions() const override;

      bool offered_suite(uint16_t ciphersuite) const override;

      std::vector<Signature_Scheme> signature_schemes() const override;

      std::vector<Group_Params> supported_ecc_curves() const override;

      std::vector<Group_Params> supported_dh_groups() const override;

      bool prefers_compressed_ec_points() const override;

      std::string sni_hostname() const override;

      bool secure_renegotiation() const override;

      std::vector<uint8_t> renegotiation_info() const override;

      bool supports_session_ticket() const override;

      std::vector<uint8_t> session_ticket() const override;

      bool supports_alpn() const override;

      bool supports_extended_master_secret() const override;

      bool supports_cert_status_message() const override;

      bool supports_encrypt_then_mac() const override;

      bool sent_signature_algorithms() const override;

      std::vector<std::string> next_protocols() const override;

      std::vector<uint16_t> srtp_profiles() const override;

      void update_hello_cookie(const Hello_Verify_Request& hello_verify) override;

      const std::vector<uint8_t>& cookie() const override;

      std::vector<uint8_t> cookie_input_data() const override;

   private:
      std::vector<uint8_t> serialize() const override;

      std::vector<uint8_t> m_hello_cookie; // DTLS only
      std::vector<uint8_t> m_cookie_input_bits; // DTLS only
   };

}

}

#endif
