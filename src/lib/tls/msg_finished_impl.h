/*
* TLS Messages
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_FINISHED_IMPL_H_
#define BOTAN_MSG_FINISHED_IMPL_H_

#include <botan/tls_handshake_msg.h>
#include <vector>

#if defined(BOTAN_HAS_CECPQ1)
  #include <botan/cecpq1.h>
#endif

namespace Botan {

namespace TLS {

class Handshake_IO;
class Handshake_State;


class Finished_Impl : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return FINISHED; }

      virtual std::vector<uint8_t> verify_data() const;

      virtual bool verify(const Handshake_State& state,
                          Connection_Side side) const;

      explicit Finished_Impl(Handshake_IO& io,
                             Handshake_State& state,
                             Connection_Side side);

      explicit Finished_Impl(const std::vector<uint8_t>& buf);

      virtual ~Finished_Impl() = 0;

      std::vector<uint8_t> serialize() const override;
   private:
      std::vector<uint8_t> m_verification_data;
   };
}

}

#endif
