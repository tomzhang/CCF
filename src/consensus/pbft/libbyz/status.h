// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "bitmap.h"
#include "message.h"
#include "parameters.h"
#include "pre_prepare.h"
#include "types.h"

//
// Status messages have the following format:
//

#pragma pack(push)
#pragma pack(1)
struct BR_info
{
  Seqno n; // Seqno of pre-prepare missing big reqs
  BR_map breqs; // Bitmap with missing big reqs.
};

struct PP_info
{
  View v; // Minimum view of missing pre-prepare
  int n; // Offset of sequence number of missing pre-prepare from ls
  int proof; // Non-zero if a proof of authenticity for request is needed
  BR_map breqs; // Bitmap with missing big reqs
};

struct Status_rep : public Message_rep
{
  View v; // Replica's current view
  Seqno ls; // seqno of last stable checkpoint
  Seqno le; // seqno of last request executed
  int id; // id of the replica that generated the message.
  short sz; // size of prepared and committed or pps
  short brsz; // size of breqs

  static const int vcs_size = (Max_num_replicas + 7) / 8;

  /* Followed by:
  if has_nv_info (extra & 1)
    char prepared[sz];   // prepared requests
    char committed[sz];  // committed requests
    BR_info breqs[brsz]; // missing big requests
  else
    char vcs[vcs_size]; // bitmap with missing view-change messages
    PP_info pps[sz];    // Array with information for missing pre-prepares
  and an authenticator generated by principal id. */
};
#pragma pack(pop)

class Status : public Message
{
  //
  //  Status messages
  //
public:
  Status(uint32_t msg_size = 0) : Message(msg_size) {}

  Status(View v, Seqno ls, Seqno le, bool hnvi, bool hnvm);
  // Effects: Creates a new unauthenticated Status message.  "v"
  // should be the sending replica's current view, "ls" should be the
  // sequence number of the last stable checkpoint, "le" the sequence
  // number of the last request executed, "hnvi" should be true iff
  // the sending replica has the complete information for view "v",
  // and "hnvm" should be true iff the sending replica has a
  // new-view message for view "v".

  //
  // Mutators when has_nv_info():
  //
  void mark_prepared(Seqno n);
  void mark_committed(Seqno n);
  // Requires: has_nv_info()
  // Effects: Marks request with sequence number "n" is prepared
  // (in view()) or is committed (in any view.) It has no effect
  // if n <= last_executed() | n > last_stable() + max_out

  void add_breqs(Seqno n, const BR_map& brs);
  // Requires: has_nv_info() && n > last_executed() & n <=
  // last_stable() + max_out
  // Effects: Records that the requests whose indices are reset in brs
  // are missing from the pre-prepare with seqno n.

  //
  // Mutators when !has_nv_info():
  //
  void mark_vcs(int i);
  // Requires: !has_nv_info()
  // Effects: Marks the view-change message from replica "i" for
  // "view()" (and any associated view-change acks) received.

  void append_pps(View v, Seqno n, const BR_map& mreqs, bool proof);
  // Requires: !has_nv_info()
  // Effects: Record that the sender is missing a pre-prepare with
  // sequence number "n" for some view greater than or equal to "v",
  // mreqs indicates what big requests might be missing, and proof
  // whether it needs prepare messages to attest to the authenticity
  // of the corresponding request.

  void authenticate();
  // Effects: Authenticates message.

  int id() const;
  // Effects: Fetches the identifier of the replica from the message.

  View view() const;
  // Effects: Returns the principal id()'s view in the message.

  bool has_nv_m() const;
  // Effects: Returns true iff principal id() has a valid new-view
  // message for view().

  bool has_nv_info() const;
  // Effects: Returns true iff principal id() has the complete
  // new-view information for view().

  Seqno last_stable() const;
  // Effects: Returns seqno of last stable checkpoint principal id()
  // has.

  Seqno last_executed() const;
  // Effects: Returns seqno of last request executed by principal id().

  //
  // Observers when has_nv_info()
  //
  bool is_prepared(Seqno n);
  bool is_committed(Seqno n);
  // Requires: has_nv_info()
  // Effects: Returns true if the request with sequence number "n" was
  // prepared (in view()) or was committed (in any view) by principal
  // id().

  class BRS_iter
  {
    // An iterator for yielding the missing requests in a status
    // message.
  public:
    BRS_iter(Status* m);
    // Requires: "m" is known to be valid and "m->has_nv_info()"
    // Effects: Return an iterator for the missing requests in "m"

    bool get(Seqno& n, BR_map& mreqs);
    // Effects: Sets "n" to the sequence number of the next missing
    // pre-prepare with missing reqs, and mreq to a bitmap with a bit
    // reset for each missing request in that pre-prepare. and returns
    // true. Unless there are no more missing pre-prepares, in which
    // case it returns false.

  private:
    Status* msg;
    int next;
  };
  friend class BRS_iter;

  //
  // Observers when !has_nv_info()
  //
  bool has_vc(int i);
  // Requires: !has_nv_info()
  // Effects: Returns true iff principal id() has a view-change
  // message from replica "id" for "view()"

  class PPS_iter
  {
    // An iterator for yielding the missing pre-prepares in a status
    // message.
  public:
    PPS_iter(Status* m);
    // Requires: "m" is known to be valid and "!m->has_nv_info()"
    // Effects: Return an iterator for the missing pre-prepares in "m"

    bool get(View& v, Seqno& n, BR_map& mreqs, bool& proof);
    // Effects: Sets "n" to the sequence number of the next missing
    // pre-prepare, "v" to its minimum view, "proof" to true iff the
    // sender needs prepare messages to attest to the authenticity of
    // the request, and returns true. Unless there are no more missing
    // pre-prepares, in which case it returns false.

  private:
    Status* msg;
    int next;
  };
  friend class PPS_iter;

  bool pre_verify();
  // Effects: Performs preliminary verification checks

private:
  Status_rep& rep() const;
  // Effects: Casts "msg" to a Status_rep&

  char* prepared();
  // Effects: Returns a pointer to the prepared bitmap

  char* committed();
  // Effects: Returns a pointer to the committed bitmap

  BR_info* breqs();
  // Effects: Returns a pointer to the breqs array.

  char* vcs();
  // Effects: Returns a pointer to the vcs bitmap

  PP_info* pps();
  // Effects: Returns a pointer to the pps array.

  void mark(Seqno n, char* set);
  // Effects: set bit in set

  bool test(Seqno n, char* set);
  // Effects: test bit in set
};

inline Status_rep& Status::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Status_rep*)msg);
}

inline char* Status::prepared()
{
  char* ret = contents() + sizeof(Status_rep);
  return ret;
}

inline char* Status::committed()
{
  char* ret = prepared() + rep().sz;
  return ret;
}

inline BR_info* Status::breqs()
{
  BR_info* ret = (BR_info*)(committed() + rep().sz);
  return ret;
}

inline char* Status::vcs()
{
  return prepared();
}

inline PP_info* Status::pps()
{
  PP_info* ret = (PP_info*)(vcs() + Status_rep::vcs_size);
  return ret;
}

inline void Status::mark(Seqno n, char* set)
{
  int offset = n - last_executed();
  if (offset > 0 && offset <= max_out)
    Bits_set(set, offset);
}

inline bool Status::test(Seqno n, char* set)
{
  int offset = n - last_executed();
  if (offset > 0 && offset <= max_out)
    return Bits_test(set, offset);
  return false;
}

inline void Status::mark_prepared(Seqno n)
{
  PBFT_ASSERT(has_nv_info(), "Invalid state");
  mark(n, prepared());
}

inline void Status::mark_committed(Seqno n)
{
  PBFT_ASSERT(has_nv_info(), "Invalid state");
  mark(n, committed());
}

inline void Status::add_breqs(Seqno n, const BR_map& brs)
{
  PBFT_ASSERT(has_nv_info(), "Invalid state");
  PBFT_ASSERT(
    n > last_executed() && n <= last_stable() + max_out, "Invalid arguments");
  PBFT_ASSERT(
    (char*)(breqs() + rep().brsz) < contents() + Max_message_size,
    "Message too small");

  BR_info& bri = breqs()[rep().brsz++];
  bri.n = n;
  bri.breqs = brs;
}

inline int Status::id() const
{
  return rep().id;
}

inline View Status::view() const
{
  return rep().v;
}

inline bool Status::has_nv_m() const
{
  return rep().extra & 2;
}

inline bool Status::has_nv_info() const
{
  return rep().extra & 1;
}

inline Seqno Status::last_stable() const
{
  return rep().ls;
}

inline Seqno Status::last_executed() const
{
  return rep().le;
}

inline bool Status::is_prepared(Seqno n)
{
  PBFT_ASSERT(has_nv_info(), "Invalid state");
  return test(n, prepared());
}

inline bool Status::is_committed(Seqno n)
{
  PBFT_ASSERT(has_nv_info(), "Invalid state");
  return test(n, committed());
}

inline bool Status::has_vc(int i)
{
  PBFT_ASSERT(!has_nv_info(), "Invalid state");
  PBFT_ASSERT(
    i >= 0 && i < Status_rep::vcs_size * BYTE_BITS, "Invalid argument");
  return Bits_test(vcs(), i);
}
