// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#include "receipt_proof.h"

#include "global_state.h"
#include "node.h"
#include "parameters.h"
#include "prepare.h"

ReceiptProof::ReceiptProof(Seqno seqno_, uint8_t num_proofs_) :
  seqno(seqno_),
  num_sigs(num_proofs_)
{}

void ReceiptProof::add_proof(
  uint8_t id,
  Seqno seqno,
  const Digest& pp_digest,
  const std::array<uint8_t, MERKLE_ROOT_SIZE>& merkle_root,
  uint64_t hashed_nonce,
  const PbftSignature& sig,
  uint32_t sig_size)
{
  auto it = proofs.find(id);
  if (it != proofs.end())
  {
    auto& proof = it->second;
    std::copy(sig.begin(), sig.end(), proof->sig.begin());
  }
  else
  {
    auto proof = std::make_unique<ReceiptProof::Proof>(
      id, seqno, pp_digest, merkle_root, hashed_nonce, sig, sig_size);
    proofs.insert({id, std::move(proof)});
  }
}

bool ReceiptProof::verify_proofs() const
{
  bool result = true;
  uint32_t count = 0;
  for (auto& p : proofs)
  {
    int node_id = p.first;
    auto& rp = p.second;

    Prepare::signature s(rp->pp_digest, rp->merkle_root, rp->hashed_nonce);

    if (node_id == pbft::GlobalState::get_node().id())
    {
      result = pbft::GlobalState::get_node().verify_signature(
        reinterpret_cast<char*>(&s),
        sizeof(s),
        (char*)rp->sig.data(),
        rp->sig_size);
    }
    else
    {
      auto sender_principal =
        pbft::GlobalState::get_node().get_principal(node_id);

      result =
        (result &&
         sender_principal->verify_signature(
           (const char*)&s,
           sizeof(Prepare::signature),
           rp->sig.data(),
           rp->sig_size));
    }
    ++count;
  }

  return result;
}

size_t ReceiptProof::get_size_of_proofs() const
{
  return proofs.size() * sizeof(ReceiptProof::Proof);
}

size_t ReceiptProof::count() const
{
  return proofs.size();
}

void ReceiptProof::copy_out_proofs(uint8_t* dest) const
{
  for (auto& proof : proofs)
  {
    auto& p = proof.second;
    std::copy(
      (uint8_t*)p.get(), (uint8_t*)p.get() + sizeof(ReceiptProof::Proof), dest);
    dest += sizeof(ReceiptProof::Proof);
  }
}