/*
* TLS Hello Request and Client Hello Messages
* (C) 2004-2011,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "msg_client_hello_impl.h"

#include <botan/tls_magic.h>

namespace Botan {

namespace TLS {

Client_Hello_Impl::~Client_Hello_Impl() {};

Handshake_Type Client_Hello_Impl::type() const
   {
   return CLIENT_HELLO;
   }

}

}
