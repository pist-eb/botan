/*
* TLS Channel - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_IMPL_13_H_
#define BOTAN_TLS_CHANNEL_IMPL_13_H_

#include <botan/internal/tls_channel_impl.h>

namespace Botan {

namespace TLS {

/**
* Generic interface for TLSv.12 endpoint
*/
class Channel_Impl_13 : public Channel_Impl
   {
   public:
      explicit Channel_Impl_13();

      explicit Channel_Impl_13(const Channel_Impl_13&) = delete;

      Channel_Impl_13& operator=(const Channel_Impl_13&) = delete;

      virtual ~Channel_Impl_13();

      size_t received_data(const uint8_t buf[], size_t buf_size) override;

      /**
      * Inject TLS traffic received from counterparty
      * @return a hint as the how many more bytes we need to process the
      *         current record (this may be 0 if on a record boundary)
      */
      size_t received_data(const std::vector<uint8_t>& buf) override;

      /**
      * Inject plaintext intended for counterparty
      * Throws an exception if is_active() is false
      */
      void send(const uint8_t buf[], size_t buf_size) override;

      /**
      * Inject plaintext intended for counterparty
      * Throws an exception if is_active() is false
      */
      void send(const std::string& val) override;

      /**
      * Send a TLS alert message. If the alert is fatal, the internal
      * state (keys, etc) will be reset.
      * @param alert the Alert to send
      */
      void send_alert(const Alert& alert) override;

      /**
      * Send a warning alert
      */
      void send_warning_alert(Alert::Type type) override { send_alert(Alert(type, false)); }

      /**
      * Send a fatal alert
      */
      void send_fatal_alert(Alert::Type type) override { send_alert(Alert(type, true)); }

      /**
      * Send a close notification alert
      */
      void close() override { send_warning_alert(Alert::CLOSE_NOTIFY); }

      /**
      * @return true iff the connection is active for sending application data
      */
      bool is_active() const override;

      /**
      * @return true iff the connection has been definitely closed
      */
      bool is_closed() const override;

      /**
      * @return certificate chain of the peer (may be empty)
      */
      std::vector<X509_Certificate> peer_cert_chain() const override;

      /**
      * Key material export (RFC 5705)
      * @param label a disambiguating label string
      * @param context a per-association context value
      * @param length the length of the desired key in bytes
      * @return key of length bytes
      */
      SymmetricKey key_material_export(const std::string& label,
                                       const std::string& context,
                                       size_t length) const override;

      /**
      * Attempt to renegotiate the session
      * @param force_full_renegotiation if true, require a full renegotiation,
      * otherwise allow session resumption
      */
      void renegotiate(bool force_full_renegotiation = false) override;

      /**
      * @return true iff the counterparty supports the secure
      * renegotiation extensions.
      */
      bool secure_renegotiation_supported() const override;

      /**
      * Perform a handshake timeout check. This does nothing unless
      * this is a DTLS channel with a pending handshake state, in
      * which case we check for timeout and potentially retransmit
      * handshake packets.
      */
      bool timeout_check() override;

   protected:
      Handshake_State& create_handshake_state(Protocol_Version version) override;
   };

}

}

#endif
