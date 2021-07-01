/*
* TLS Server Hello Impl
* (C) 2004-2011,2015,2016,2019 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

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
                                     const Client_Hello& client_hello,
                                     const Server_Hello::Settings& server_settings,
                                     const std::string next_protocol) :
   m_version(server_settings.protocol_version()),
   m_session_id(server_settings.session_id()),
   m_random(make_server_hello_random(rng, m_version, policy)),
   m_ciphersuite(server_settings.ciphersuite()),
   m_comp_method(0)
   {
   if(client_hello.supports_extended_master_secret())
      {
      m_extensions.add(new Extended_Master_Secret);
      }

   // Sending the extension back does not commit us to sending a stapled response
   if(client_hello.supports_cert_status_message() && policy.support_cert_status_message())
      {
      m_extensions.add(new Certificate_Status_Request);
      }

   if(!next_protocol.empty() && client_hello.supports_alpn())
      {
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocol));
      }
   }

// Resuming
Server_Hello_Impl::Server_Hello_Impl(const Policy& policy,
                                     RandomNumberGenerator& rng,
                                     const Client_Hello& client_hello,
                                     Session& resumed_session,
                                     const std::string next_protocol) :
   m_version(resumed_session.version()),
   m_session_id(client_hello.session_id()),
   m_random(make_hello_random(rng, policy)),
   m_ciphersuite(resumed_session.ciphersuite_code()),
   m_comp_method(0)
   {
   if(client_hello.supports_extended_master_secret())
      {
      m_extensions.add(new Extended_Master_Secret);
      }

   if(!next_protocol.empty() && client_hello.supports_alpn())
      {
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocol));
      }
   }

Server_Hello_Impl::~Server_Hello_Impl() = default;

Handshake_Type Server_Hello_Impl::type() const
   {
   return SERVER_HELLO;
   }

Protocol_Version Server_Hello_Impl::version() const
   {
   return m_version;
   }

const std::vector<uint8_t>& Server_Hello_Impl::random() const
   {
   return m_random;
   }

const std::vector<uint8_t>& Server_Hello_Impl::session_id() const
   {
   return m_session_id;
   }

uint16_t Server_Hello_Impl::ciphersuite() const
   {
   return m_ciphersuite;
   }

uint8_t Server_Hello_Impl::compression_method() const
   {
   return m_comp_method;
   }

bool Server_Hello_Impl::supports_extended_master_secret() const
   {
   return m_extensions.has<Extended_Master_Secret>();
   }

bool Server_Hello_Impl::supports_certificate_status_message() const
   {
   return m_extensions.has<Certificate_Status_Request>();
   }

std::string Server_Hello_Impl::next_protocol() const
   {
   if(auto alpn = m_extensions.get<Application_Layer_Protocol_Notification>())
      {
      return alpn->single_protocol();
      }
   return "";
   }

std::set<Handshake_Extension_Type> Server_Hello_Impl::extension_types() const
   {
   return m_extensions.extension_types();
   }

const Extensions& Server_Hello_Impl::extensions() const
   {
   return m_extensions;
   }

}

}
