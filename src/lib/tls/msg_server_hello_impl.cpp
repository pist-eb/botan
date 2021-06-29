/*
* TLS Server Hello and Server Hello Done
* (C) 2004-2011,2015,2016,2019 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/tls_callbacks.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/msg_server_hello_impl.h>

namespace Botan {

namespace TLS {

class Client_Hello;

namespace {

std::vector<uint8_t>
make_server_hello_random(RandomNumberGenerator& rng,
                         Protocol_Version offered_version,
                         const Policy& policy)
   {
   BOTAN_UNUSED(offered_version, policy);
   auto random = make_hello_random(rng, policy);
   return random;
   }

}

Server_Hello_Impl::Server_Hello_Impl() = default;

// New session case
Server_Hello_Impl::Server_Hello_Impl(const Policy& policy,
                                     RandomNumberGenerator& rng,
                                     const Server_Hello::Settings& server_settings) :
   m_version(server_settings.protocol_version()),
   m_session_id(server_settings.session_id()),
   m_random(make_server_hello_random(rng, m_version, policy)),
   m_ciphersuite(server_settings.ciphersuite()),
   m_comp_method(0)
   {
   }

// Resuming
Server_Hello_Impl::Server_Hello_Impl(const Policy& policy,
                                     RandomNumberGenerator& rng,
                                     const Client_Hello& client_hello,
                                     Session& resumed_session) :
   m_version(resumed_session.version()),
   m_session_id(client_hello.session_id()),
   m_random(make_hello_random(rng, policy)),
   m_ciphersuite(resumed_session.ciphersuite_code()),
   m_comp_method(0)
   {
   }

Server_Hello_Impl::~Server_Hello_Impl() = default;

Handshake_Type Server_Hello_Impl::type() const 
   {
   return SERVER_HELLO;
   }

}

}
