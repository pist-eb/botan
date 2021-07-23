/*
* TLS Channel - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_impl_13.h>

namespace Botan {

namespace TLS {

Channel_Impl_13::Channel_Impl_13(Callbacks& callbacks,
                                 Session_Manager& session_manager,
                                 RandomNumberGenerator& rng,
                                 const Policy& policy,
                                 bool is_server,
                                 size_t reserved_io_buffer_size) :
   m_callbacks(callbacks),
   m_session_manager(session_manager),
   m_rng(rng),
   m_policy(policy),
   m_is_server(is_server),
   m_has_been_closed(false)
   {
   m_writebuf.reserve(reserved_io_buffer_size);
   m_readbuf.reserve(reserved_io_buffer_size);
   }

Channel_Impl_13::~Channel_Impl_13() = default;

size_t Channel_Impl_13::received_data(const uint8_t buf[], size_t buf_size)
   {
   BOTAN_UNUSED(buf, buf_size);

   return 0;
   }

size_t Channel_Impl_13::received_data(const std::vector<uint8_t>& buf)
   {
   return this->received_data(buf.data(), buf.size());
   }

void Channel_Impl_13::send(const uint8_t buf[], size_t buf_size)
   {
   BOTAN_UNUSED(buf, buf_size);

   return;
   }

void Channel_Impl_13::send(const std::string& val) 
   {
   this->send(cast_char_ptr_to_uint8(val.data()), val.size());
   }

void Channel_Impl_13::send_alert(const Alert& alert)
   {
   BOTAN_UNUSED(alert);
   }

bool Channel_Impl_13::is_active() const
   {
   return !is_closed();
   }

bool Channel_Impl_13::is_closed() const
   {
   return m_has_been_closed;
   }

std::vector<X509_Certificate> Channel_Impl_13::peer_cert_chain() const
   {
   return std::vector<X509_Certificate>();
   }

SymmetricKey Channel_Impl_13::key_material_export(const std::string& label,
                                 const std::string& context,
                                 size_t length) const
   {
   BOTAN_UNUSED(label, context, length);

   return SymmetricKey();
   }

void Channel_Impl_13::renegotiate(bool force_full_renegotiation)
   {
   BOTAN_UNUSED(force_full_renegotiation);
   }

bool Channel_Impl_13::secure_renegotiation_supported() const
   {
   return false;
   }

bool Channel_Impl_13::timeout_check()
   {
   return false;
   }

Handshake_State& Channel_Impl_13::create_handshake_state(Protocol_Version version)
   {
   BOTAN_UNUSED(version);
   }

}

}
