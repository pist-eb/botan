/*
* Certificate Message
* (C) 2004-2006,2012,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/msg_certificate_impl.h>
#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_alert.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/loadstor.h>
#include <botan/data_src.h>

namespace Botan {

namespace TLS {

Handshake_Type Certificate_Impl::type() const
   {
   return CERTIFICATE;
   }

Certificate_Impl::~Certificate_Impl() = default;

}

}
