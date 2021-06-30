/*
* TLS Messages
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_CERT_REQ_IMPL_12_H_
#define BOTAN_MSG_CERT_REQ_IMPL_12_H_

#include <botan/tls_extensions.h>
#include <botan/tls_handshake_msg.h>
#include <botan/tls_session.h>
#include <botan/tls_policy.h>
#include <botan/tls_ciphersuite.h>
#include <botan/pk_keys.h>
#include <botan/x509cert.h>
#include <botan/ocsp.h>
#include <botan/internal/msg_cert_req_impl.h>

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

class Session;
class Handshake_IO;
class Handshake_State;
class Callbacks;
class Client_Hello_Impl;
class Server_Hello_Impl_12;
class Certificate_Verify_Impl;
class Finished_Impl;


/**
* Certificate Request Message
*/
class BOTAN_UNSTABLE_API Certificate_Req_Impl_12 final : public Certificate_Req_Impl
   {
   public:
      const std::vector<std::string>& acceptable_cert_types() const override;

      const std::vector<X509_DN>& acceptable_CAs() const override;

      const std::vector<Signature_Scheme>& signature_schemes() const override;

      explicit Certificate_Req_Impl_12(Handshake_IO& io,
                      Handshake_Hash& hash,
                      const Policy& policy,
                      const std::vector<X509_DN>& allowed_cas);

      explicit Certificate_Req_Impl_12(const std::vector<uint8_t>& buf);

      std::vector<uint8_t> serialize() const override;

   private:
      std::vector<X509_DN> m_names;
      std::vector<std::string> m_cert_key_types;
      std::vector<Signature_Scheme> m_schemes;
   };
}

}

#endif
