/*
* TLS Client Hello Message - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>
#include <botan/tls_session.h>
#include <botan/rng.h>
#include <botan/hash.h>

#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/msg_client_hello_impl_13.h>

namespace Botan {

namespace TLS {

/*
* Create a new Client Hello message
*/
Client_Hello_Impl_13::Client_Hello_Impl_13(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Client_Hello::Settings& client_settings,
                           const std::vector<std::string>& next_protocols) :
   Client_Hello_Impl(io, hash, policy, cb, rng, reneg_info, client_settings, next_protocols)
   {
   // Always use TLS 1.2 as a legacy version
   m_version = Protocol_Version::TLS_V12;

   /*
   * Place all empty extensions in front to avoid a bug in some systems
   * which reject hellos when the last extension in the list is empty.
   */
   m_extensions.add(new Extended_Master_Secret);

   m_extensions.add(new Supported_Versions(client_settings.protocol_version(), policy));

   cb.tls_modify_extensions(m_extensions, CLIENT);

   hash.update(io.send(*this));
   }

/*
* Create a new Client Hello message (session resumption case)
*/
Client_Hello_Impl_13::Client_Hello_Impl_13(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Session& session,
                           const std::vector<std::string>& next_protocols) :
   Client_Hello_Impl(io, hash, policy, cb, rng, reneg_info, session, next_protocols)
   {
   // Always use TLS 1.2 as a legacy version
   m_version = Protocol_Version::TLS_V12;

   /*
   * Place all empty extensions in front to avoid a bug in some systems
   * which reject hellos when the last extension in the list is empty.
   */
   m_extensions.add(new Extended_Master_Secret);

   m_extensions.add(new Supported_Versions(session.version(), policy));

   cb.tls_modify_extensions(m_extensions, CLIENT);

   hash.update(io.send(*this));
   }

Client_Hello_Impl_13::Client_Hello_Impl_13(const std::vector<uint8_t>& buf) :
   Client_Hello_Impl(buf)
   {
   // Common implementation is enough, as received Client_Hello shall be read correctly independent on the version
   }

}

}