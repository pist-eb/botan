/*
* TLS Client - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_client_impl_13.h>
#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_client_impl.h>

#include <botan/credentials_manager.h>

namespace Botan {

namespace TLS {

/*
* TLS 1.3 Client  Constructor
*/
Client_Impl_13::Client_Impl_13(Callbacks& callbacks,
                               Session_Manager& session_manager,
                               Credentials_Manager& creds,
                               const Policy& policy,
                               RandomNumberGenerator& rng,
                               const Server_Information& info,
                               const Protocol_Version& offer_version,
                               const std::vector<std::string>& next_protocols,
                               size_t io_buf_sz) :
   Channel_Impl_13(callbacks, session_manager, rng, policy,
                   false, io_buf_sz),
   Client_Impl(static_cast<Channel_Impl&>(*this))
   {
   BOTAN_UNUSED(creds, info, offer_version, next_protocols);
   }

std::vector<X509_Certificate> Client_Impl_13::get_peer_cert_chain(const Handshake_State& state) const
   {
   BOTAN_UNUSED(state);

   return std::vector<X509_Certificate>();
   }

void Client_Impl_13::initiate_handshake(Handshake_State& state,
                                        bool force_full_renegotiation)
   {
   BOTAN_UNUSED(state, force_full_renegotiation);
   }

void Client_Impl_13::process_handshake_msg(const Handshake_State* active_state,
                                           Handshake_State& pending_state,
                                           Handshake_Type type,
                                           const std::vector<uint8_t>& contents,
                                           bool epoch0_restart)
   {
   BOTAN_UNUSED(active_state, pending_state, type, contents, epoch0_restart);
   }

std::unique_ptr<Handshake_State> Client_Impl_13::new_handshake_state(std::unique_ptr<Handshake_IO> io)
   {
   BOTAN_UNUSED(io);
   }

}

}
