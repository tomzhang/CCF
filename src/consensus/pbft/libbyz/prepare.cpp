// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "prepare.h"

#include "message_tags.h"
#include "node.h"
#include "pbft_assert.h"
#include "principal.h"
#include "replica.h"

uint64_t get_nonce_hash(uint64_t nonce)
{
  Digest dh;
  Digest::Context context;
  dh.update_last(context, (char*)&nonce, sizeof(uint64_t));
  dh.finalize(context);
  return dh.hash();
}

Prepare::Prepare(
  View v,
  Seqno s,
  Digest& pp_d,
  uint64_t nonce_,
  Principal* dst,
  bool is_signed,
  int id,
  bool should_sign) :
  Prepare(
    v, s, pp_d, nonce_, get_nonce_hash(nonce_), dst, is_signed, id, should_sign)
{}

Prepare::Prepare(
  View v,
  Seqno s,
  Digest& pp_d,
  uint64_t nonce_,
  uint64_t hashed_nonce_,
  Principal* dst,
  bool is_signed,
  int id,
  bool should_sign) :
  Message(
    Prepare_tag,
    sizeof(Prepare_rep)
#ifndef USE_PKEY
      + ((dst) ? MAC_size : pbft::GlobalState::get_node().auth_size())),
#else
      + ((dst) ? MAC_size : pbft_max_signature_size)),
#endif
  nonce(nonce_)
{
  rep().extra = (dst) ? 1 : 0;
  rep().view = v;
  rep().seqno = s;
  rep().digest = pp_d;

  if (id < 0)
  {
    rep().id = pbft::GlobalState::get_node().id();
  }

  rep().hashed_nonce = hashed_nonce_;

#ifdef SIGN_BATCH
  if (!is_signed)
  {
    rep().batch_digest_signature.fill(0);
  }
#endif

#ifdef USE_PKEY
  rep().prepare_sig_size = 0;
#endif

  rep().padding = 0;
  if (!dst)
  {
#ifndef USE_PKEY
    auth_type = Auth_type::out;
    auth_len = sizeof(Prepare_rep);
    auth_src_offset = 0;
#else
    if (should_sign)
    {
      rep().prepare_sig_size = pbft::GlobalState::get_node().gen_signature(
        contents(), sizeof(Prepare_rep), contents() + sizeof(Prepare_rep));
    }
#endif
  }
  else
  {
    auth_type = Auth_type::out;
    auth_len = sizeof(Prepare_rep);
    auth_src_offset = 0;
    auth_dst_offset = sizeof(Prepare_rep);
  }
}

void Prepare::re_authenticate(Principal* p)
{
  if (rep().extra == 0)
  {
#ifndef USE_PKEY
    auth_type = Auth_type::out;
    auth_len = sizeof(Prepare_rep);
    auth_src_offset = 0;
#endif
  }
  else
  {
    // p->gen_mac_out(contents(), sizeof(Prepare_rep),
    // contents()+sizeof(Prepare_rep));

    auth_type = Auth_type::out;
  }
  auth_len = sizeof(Prepare_rep);
  auth_src_offset = 0;
  auth_dst_offset = sizeof(Prepare_rep);
}

bool Prepare::pre_verify()
{
  // special case for f == 0
  if (pbft::GlobalState::get_replica().f() == 0)
  {
    return true;
  }

  // This type of message should only be sent by a replica other than me
  // and different from the primary
  if (
    !pbft::GlobalState::get_node().is_replica(id()) ||
    id() == pbft::GlobalState::get_node().id())
  {
    return false;
  }

  auto sender_principal = pbft::GlobalState::get_node().get_principal(rep().id);
  if (
    !sender_principal->has_certificate_set() &&
    pbft::GlobalState::get_node().f() == 0)
  {
    // Do not verify signature of first pre-prepare since node certificate
    // required for verification is contained in the pre-prepare requests
    return true;
  }

  Prepare::signature s(pp_digest, pp_merkle_root, rep().hashed_nonce);

  if (!sender_principal->verify_signature(
        (const char*)&s,
        sizeof(Prepare::signature),
        rep().batch_digest_signature.data(),
        rep().digest_sig_size))
  {
    // NOTE: this is fixed in master, will not have a perf impact
    // LOG_INFO << "failed to verify signature on the digest, seqno:"
    //         << rep().seqno << ", ms:" << rep().id << std::endl;
    // return false;
  }

  if (rep().extra == 0)
  {
    // Check signature size.
#ifndef USE_PKEY
    if (
      view() % pbft::GlobalState::get_replica().num_of_replicas() == id() ||
      size() - (int)sizeof(Prepare_rep) <
        pbft::GlobalState::get_node().auth_size(id()))
    {
      return false;
    }

    return true;
#else
    if (
      view() % pbft::GlobalState::get_replica().num_of_replicas() == id() ||
      size() - (int)sizeof(Prepare_rep) < pbft_max_signature_size)
    {
      return false;
    }
    return true;
#endif
  }
  else
  {
    if (size() - (int)sizeof(Prepare_rep) < MAC_size)
    {
      return false;
    }

    return true;
  }

  assert(false);
  return false;
}

size_t Prepare::Sign(
  PbftSignature& result,
  const std::array<uint8_t, MERKLE_ROOT_SIZE>& merkle_root,
  uint64_t hashed_nonce,
  const Digest& pp_d)
{
  signature s(pp_d, merkle_root, hashed_nonce);

  return pbft::GlobalState::get_node().gen_signature(
    reinterpret_cast<char*>(&s), sizeof(s), result);
}
void Prepare::save_signature(PbftSignature& signature, size_t signature_size)
{
  rep().digest_sig_size = signature_size;
  rep().batch_digest_signature = signature;
}