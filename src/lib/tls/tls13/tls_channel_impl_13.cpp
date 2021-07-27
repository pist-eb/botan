/*
* TLS Channel - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_record.h>

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
   /* epoch 0 is plaintext, thus null cipher state */
   m_write_cipher_states[0] = nullptr;
   m_read_cipher_states[0] = nullptr;

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
   if(handshake_state())
      throw Internal_Error("create_handshake_state called multiple times");

   if(!m_sequence_numbers)
      {
      m_sequence_numbers.reset(new Stream_Sequence_Numbers);
      }

   using namespace std::placeholders;

   std::unique_ptr<Handshake_IO> io = std::make_unique<Stream_Handshake_IO>(
     std::bind(&Channel_Impl_13::send_record, this, _1, _2));

   m_handshake_state = new_handshake_state(std::move(io));

   return *m_handshake_state.get();
   }


void Channel_Impl_13::write_record(Connection_Cipher_State* cipher_state, uint16_t epoch,
                                   uint8_t record_type, const uint8_t input[], size_t length)
   {
   BOTAN_ASSERT(handshake_state(), "Handshake state exists");

   const Protocol_Version record_version = handshake_state()->version();

   const uint64_t next_seq = sequence_numbers().next_write_sequence(epoch);

   if(cipher_state == nullptr)
      {
      TLS::write_unencrypted_record(m_writebuf, record_type, record_version, next_seq,
                                    input, length);
      }
   else
      {
      TLS::write_record(m_writebuf, record_type, record_version, next_seq,
                        input, length, *cipher_state, m_rng);
      }

   callbacks().tls_emit_data(m_writebuf.data(), m_writebuf.size());
   }

void Channel_Impl_13::send_record_array(uint16_t epoch, uint8_t type, const uint8_t input[], size_t length)
   {
   if(length == 0)
      return;

   auto cipher_state = write_cipher_state_epoch(epoch);

   while(length)
      {
      const size_t sending = std::min<size_t>(length, MAX_PLAINTEXT_SIZE);
      write_record(cipher_state.get(), epoch, type, input, sending);

      input += sending;
      length -= sending;
      }
   }

void Channel_Impl_13::send_record(uint8_t record_type, const std::vector<uint8_t>& record)
   {
   send_record_array(sequence_numbers().current_write_epoch(),
                     record_type, record.data(), record.size());
   }

Connection_Sequence_Numbers& Channel_Impl_13::sequence_numbers() const
   {
   BOTAN_ASSERT(m_sequence_numbers, "Have a sequence numbers object");
   return *m_sequence_numbers;
   }

std::shared_ptr<Connection_Cipher_State> Channel_Impl_13::read_cipher_state_epoch(uint16_t epoch) const
   {
   auto i = m_read_cipher_states.find(epoch);
   if(i == m_read_cipher_states.end())
      { throw Internal_Error("TLS::Channel_Impl_13 No read cipherstate for epoch " + std::to_string(epoch)); }
   return i->second;
   }

std::shared_ptr<Connection_Cipher_State> Channel_Impl_13::write_cipher_state_epoch(uint16_t epoch) const
   {
   auto i = m_write_cipher_states.find(epoch);
   if(i == m_write_cipher_states.end())
      { throw Internal_Error("TLS::Channel_Impl_13 No write cipherstate for epoch " + std::to_string(epoch)); }
   return i->second;
   }

}

}
