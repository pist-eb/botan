/*
* TLS Channels
* (C) 2011,2012,2014,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_channel.h>
#include <botan/tls_policy.h>
#include <botan/tls_messages.h>
#include <botan/kdf.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace TLS {

Channel::~Channel() = default;

size_t TLS::Channel::IO_BUF_DEFAULT_SIZE = 10*1024;

}

}
