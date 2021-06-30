/*
* TLS Hello Request and Client Hello Messages
* (C) 2004-2011,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/msg_client_hello_impl.h>
#include <botan/tls_policy.h>
#include <botan/tls_magic.h>
#include <botan/tls_session.h>

namespace Botan {

namespace TLS {

Client_Hello_Impl::Client_Hello_Impl() = default;

Client_Hello_Impl::Client_Hello_Impl(const Policy& policy,
                        RandomNumberGenerator& rng,
                        const Client_Hello::Settings& client_settings) :
   m_version(client_settings.protocol_version()),
   m_random(make_hello_random(rng, policy)),
   m_suites(policy.ciphersuite_list(m_version)),
   m_comp_methods(1)
   {
   }

Client_Hello_Impl::Client_Hello_Impl(const Policy& policy,
                           RandomNumberGenerator& rng,
                           const Session& session) :
   m_version(session.version()),
   m_session_id(session.session_id()),
   m_random(make_hello_random(rng, policy)),
   m_suites(policy.ciphersuite_list(m_version)),
   m_comp_methods(1)
   {
   }

Client_Hello_Impl::~Client_Hello_Impl() = default;

Handshake_Type Client_Hello_Impl::type() const
   {
   return CLIENT_HELLO;
   }

}

}
