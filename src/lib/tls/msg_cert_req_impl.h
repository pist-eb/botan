/*
* TLS Messages
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CERT_REQ_IMPL_H_
#define BOTAN_TLS_CERT_REQ_IMPL_H_

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
class BOTAN_UNSTABLE_API Certificate_Req_Impl : public Handshake_Message
   {
   public:
      Handshake_Type type() const override;

      virtual const std::vector<std::string>& acceptable_cert_types() const = 0;

      virtual const std::vector<X509_DN>& acceptable_CAs() const = 0;

      virtual const std::vector<Signature_Scheme>& signature_schemes() const = 0;

      Certificate_Req_Impl();

      virtual ~Certificate_Req_Impl();
   };
}

}

#endif
