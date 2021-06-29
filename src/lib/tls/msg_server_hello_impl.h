/*
* TLS Messages
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_SERVER_HELLO_IMPL_H_
#define BOTAN_TLS_SERVER_HELLO_IMPL_H_

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
#include <memory>


namespace Botan {

namespace TLS {

class Client_Hello;
class Session;
class Handshake_IO;
class Callbacks;

/**
* Server Hello Impl Message
*/
class Server_Hello_Impl : public Handshake_Message
   {
   public:
      Server_Hello_Impl();

      Server_Hello_Impl(const Policy& policy,
                        RandomNumberGenerator& rng,
                        const Server_Hello::Settings& settings);

      Server_Hello_Impl(const Policy& policy,
                        RandomNumberGenerator& rng,
                        const Client_Hello& client_hello,
                        Session& resumed_session);

      virtual ~Server_Hello_Impl();

      Handshake_Type type() const override;

      virtual Protocol_Version version() const;

      virtual const std::vector<uint8_t>& random() const;

      virtual const std::vector<uint8_t>& session_id() const;

      virtual uint16_t ciphersuite() const;

      virtual uint8_t compression_method() const;

      virtual bool secure_renegotiation() const = 0;

      virtual std::vector<uint8_t> renegotiation_info() const = 0;

      virtual bool supports_extended_master_secret() const = 0;

      virtual bool supports_encrypt_then_mac() const = 0;

      virtual bool supports_certificate_status_message() const = 0;

      virtual bool supports_session_ticket() const = 0;

      virtual uint16_t srtp_profile() const = 0;

      virtual std::string next_protocol() const = 0;

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
