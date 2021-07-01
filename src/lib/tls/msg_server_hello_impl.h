/*
* TLS Server Hello Impl
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_SERVER_HELLO_IMPL_H_
#define BOTAN_MSG_SERVER_HELLO_IMPL_H_

#include <botan/tls_messages.h>
#include <botan/tls_handshake_msg.h>
#include <vector>
#include <string>

namespace Botan {

class RandomNumberGenerator;

namespace TLS {

class Client_Hello;
class Policy;
class Session;

/**
* Server Hello Impl Message
*/
class Server_Hello_Impl : public Handshake_Message
   {
   public:
      explicit Server_Hello_Impl();

      explicit Server_Hello_Impl(const Policy& policy,
                        RandomNumberGenerator& rng,
                        const Client_Hello& client_hello,
                        const Server_Hello::Settings& settings,
                        const std::string next_protocol);

      explicit Server_Hello_Impl(const Policy& policy,
                        RandomNumberGenerator& rng,
                        const Client_Hello& client_hello,
                        Session& resumed_session,
                        const std::string next_protocol);

      virtual ~Server_Hello_Impl() = 0;

      Handshake_Type type() const override;

      virtual Protocol_Version version() const;

      virtual const std::vector<uint8_t>& random() const;

      virtual const std::vector<uint8_t>& session_id() const;

      virtual uint16_t ciphersuite() const;

      virtual uint8_t compression_method() const;

      virtual bool secure_renegotiation() const = 0;

      virtual std::vector<uint8_t> renegotiation_info() const = 0;

      virtual bool supports_extended_master_secret() const;

      virtual bool supports_encrypt_then_mac() const = 0;

      virtual bool supports_certificate_status_message() const;

      virtual bool supports_session_ticket() const = 0;

      virtual uint16_t srtp_profile() const = 0;

      virtual std::string next_protocol() const;

      virtual std::set<Handshake_Extension_Type> extension_types() const;

      virtual const Extensions& extensions() const;

      virtual bool prefers_compressed_ec_points() const = 0;

      virtual bool random_signals_downgrade() const = 0;

   protected:
      Protocol_Version m_version;
      std::vector<uint8_t> m_session_id, m_random;
      uint16_t m_ciphersuite;
      uint8_t m_comp_method;

      Extensions m_extensions;
   };

}

}

#endif //BOTAN_TLS_SERVER_HELLO_IMPL_H_
