/*
* TLS Client - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CLIENT_IMPL_13_H_
#define BOTAN_TLS_CLIENT_IMPL_13_H_

#include <botan/internal/tls_client_impl.h>
#include <botan/internal/tls_channel_impl_13.h>

namespace Botan {

namespace TLS {

/**
* SSL/TLS Client 1.3 implementation
*/
class Client_Impl_13 : public Channel_Impl_13, public Client_Impl
   {
   public:
      explicit Client_Impl_13();

      /**
      * @return network protocol as advertised by the TLS server, if server sent the ALPN extension
      */
      std::string application_protocol() const override { return m_application_protocol; }

   private:
      std::vector<X509_Certificate>
         get_peer_cert_chain(const Handshake_State& state) const override;

      void initiate_handshake(Handshake_State& state,
                              bool force_full_renegotiation) override;

      void process_handshake_msg(const Handshake_State* active_state,
                                 Handshake_State& pending_state,
                                 Handshake_Type type,
                                 const std::vector<uint8_t>& contents,
                                 bool epoch0_restart) override;

      std::unique_ptr<Handshake_State> new_handshake_state(std::unique_ptr<Handshake_IO> io) override;

   private:
      std::string m_application_protocol;
   };

}

}

#endif
