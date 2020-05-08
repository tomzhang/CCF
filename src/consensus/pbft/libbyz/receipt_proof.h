// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "digest.h"
#include "parameters.h"
#include "types.h"

class ReceiptProof
{
public:
  struct Proof
  {
    Proof(
      int id_,
      Seqno seqno_,
      const Digest& pp_digest_,
      const std::array<uint8_t, MERKLE_ROOT_SIZE>& merkle_root_,
      uint64_t hashed_nonce_,
      const PbftSignature& sig_,
      uint32_t sig_size_) :
      id(id_),
      seqno(seqno_),
      pp_digest(pp_digest_),
      merkle_root(merkle_root_),
      hashed_nonce(hashed_nonce_),
      sig(sig_),
      sig_size(sig_size_)
    {}

    Seqno seqno;
    Digest pp_digest;
    int id;
    std::array<uint8_t, MERKLE_ROOT_SIZE> merkle_root;
    uint64_t hashed_nonce;
    PbftSignature sig;
    uint32_t sig_size;
  };

public:
  ReceiptProof(Seqno seqno, uint8_t num_proofs);

  void add_proof(
    uint8_t id,
    Seqno seqno,
    const Digest& pp_digest,
    const std::array<uint8_t, MERKLE_ROOT_SIZE>& merkle_root,
    uint64_t hashed_nonce,
    const PbftSignature& sig,
    uint32_t sig_size);

  bool verify_proofs() const;

  size_t get_size_of_proofs() const;

  void copy_out_proofs(uint8_t* dest) const;

  size_t count() const;

  Seqno get_seqno() const
  {
    return seqno;
  }

private:
  uint8_t num_sigs; // size of the buffer that follows the receipts
  Seqno seqno; // seqno of this receipt proof message

  std::map<int, std::unique_ptr<ReceiptProof::Proof>>
    proofs; // maps node_id to where its proof is
};