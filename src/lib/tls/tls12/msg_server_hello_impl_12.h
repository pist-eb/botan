/*
* TLS Messages
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_SERVER_HELLO_IMPL_12_H_
#define BOTAN_TLS_SERVER_HELLO_IMPL_12_H_

#include <botan/tls_extensions.h>
#include <botan/tls_handshake_msg.h>
#include <botan/tls_session.h>
#include <botan/tls_policy.h>
#include <botan/tls_ciphersuite.h>
#include <botan/internal/msg_server_hello_impl.h>
#include <botan/pk_keys.h>
#include <botan/x509cert.h>
#include <botan/ocsp.h>
#include <vector>
#include <string>
#include <set>
#include <memory>

#if defined(BOTAN_HAS_CECPQ1)
  #include <botan/cecpq1.h>
#endif

namespace Botan {

class Public_Key;
class Credentials_Manager;

namespace TLS {

class Client_Hello;
class Session;
class Handshake_IO;
class Handshake_State;
class Callbacks;

std::vector<uint8_t> make_hello_random(RandomNumberGenerator& rng,
                                       const Policy& policy);

/**
* Server Hello Message
*/
class BOTAN_UNSTABLE_API Server_Hello_Impl_12 final : public Server_Hello_Impl
   {
   public:
      Server_Hello_Impl_12(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& secure_reneg_info,
                           const Client_Hello& client_hello,
                           const Server_Hello::Settings& settings,
                           const std::string next_protocol);

      Server_Hello_Impl_12(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& secure_reneg_info,
                           const Client_Hello& client_hello,
                           Session& resumed_session,
                           bool offer_session_ticket,
                           const std::string& next_protocol);

      explicit Server_Hello_Impl_12(const std::vector<uint8_t>& buf);

      Handshake_Type type() const override { return SERVER_HELLO; }

      const std::vector<uint8_t>& random() const override { return m_random; }

      const std::vector<uint8_t>& session_id() const override { return m_session_id; }

      uint16_t ciphersuite() const override { return m_ciphersuite; }

      uint8_t compression_method() const override { return m_comp_method; }

      bool secure_renegotiation() const override
         {
         return m_extensions.has<Renegotiation_Extension>();
         }

      std::vector<uint8_t> renegotiation_info() const override
         {
         if(Renegotiation_Extension* reneg = m_extensions.get<Renegotiation_Extension>())
            return reneg->renegotiation_info();
         return std::vector<uint8_t>();
         }

      bool supports_extended_master_secret() const override
         {
         return m_extensions.has<Extended_Master_Secret>();
         }

      bool supports_encrypt_then_mac() const override
         {
         return m_extensions.has<Encrypt_then_MAC>();
         }

      bool supports_certificate_status_message() const override
         {
         return m_extensions.has<Certificate_Status_Request>();
         }

      bool supports_session_ticket() const override
         {
         return m_extensions.has<Session_Ticket>();
         }

      uint16_t srtp_profile() const override
         {
         if(auto srtp = m_extensions.get<SRTP_Protection_Profiles>())
            {
            auto prof = srtp->profiles();
            if(prof.size() != 1 || prof[0] == 0)
               throw Decoding_Error("Server sent malformed DTLS-SRTP extension");
            return prof[0];
            }

         return 0;
         }

      std::string next_protocol() const override
         {
         if(auto alpn = m_extensions.get<Application_Layer_Protocol_Notification>())
            return alpn->single_protocol();
         return "";
         }

      std::set<Handshake_Extension_Type> extension_types() const override
         { return m_extensions.extension_types(); }

      const Extensions& extensions() const override { return m_extensions; }

      bool prefers_compressed_ec_points() const override
         {
         if(auto ecc_formats = m_extensions.get<Supported_Point_Formats>())
            {
            return ecc_formats->prefers_compressed();
            }
         return false;
         }

      bool random_signals_downgrade() const override;
      
      std::vector<uint8_t> serialize() const override;
   };

}

}

#endif //BOTAN_TLS_SERVER_HELLO_IMPL_12_H_
