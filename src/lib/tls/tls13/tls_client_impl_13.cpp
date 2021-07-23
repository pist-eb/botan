/*
* TLS Client - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_client_impl_13.h>
#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_client_impl.h>

namespace Botan {

namespace TLS {

/*
* TLS 1.3 Client  Constructor
*/
Client_Impl_13::Client_Impl_13() :
   Channel_Impl_13(),
   Client_Impl(static_cast<Channel_Impl&>(*this))
   {

   }

std::vector<X509_Certificate> Client_Impl_13::get_peer_cert_chain(const Handshake_State& state) const
   {
   return std::vector<X509_Certificate>();
   }

void Client_Impl_13::initiate_handshake(Handshake_State& state,
                                        bool force_full_renegotiation)
   {

   }

void Client_Impl_13::process_handshake_msg(const Handshake_State* active_state,
                                           Handshake_State& pending_state,
                                           Handshake_Type type,
                                           const std::vector<uint8_t>& contents,
                                           bool epoch0_restart)
   {

   }

std::unique_ptr<Handshake_State> Client_Impl_13::new_handshake_state(std::unique_ptr<Handshake_IO> io)
   {

   }

}

}
