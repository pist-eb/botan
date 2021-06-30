/*
* Finished Message
* (C) 2004-2006,2012 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/kdf.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/msg_finished_impl_12.h>

namespace Botan {

namespace TLS {

/*
* Create a new Finished message
*/
Finished::Finished(Handshake_IO& io,
                   Handshake_State& state,
                   Connection_Side side) :
   m_impl(std::make_unique<Finished_Impl_12>(io, state, side))
   {
   }

/*
* Serialize a Finished message
*/
std::vector<uint8_t> Finished::serialize() const
   {
   return m_impl->serialize();
   }

/*
* Deserialize a Finished message
*/
Finished::Finished(const std::vector<uint8_t>& buf) :
   m_impl(std::make_unique<Finished_Impl_12>(buf))
   {
   }

Finished::~Finished() = default;


std::vector<uint8_t> Finished::verify_data() const
   {
   return m_impl->verify_data();
   }

/*
* Verify a Finished message
*/
bool Finished::verify(const Handshake_State& state,
                      Connection_Side side) const
   {
   return m_impl->verify(state, side);
   }
}

}
