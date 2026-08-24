# Proto RFCs

Fifteen proposed changes to `github.com/agile-crypto/api`, found while reconciling this C binding
against the real wire specification (see `RECONCILIATION_PLAN.md` §5 for the original list, §9.3
for the discussion of why RFC-04 in particular is not optional). Each RFC that has a corresponding
C function today has it in `include/agc/agc_ext.h`, gated behind `AGC_ENABLE_PROPOSED_EXTENSIONS`
and excluded from Tier 1b/1c conformance (D16): the core's "exactly 90 RPCs" claim must stay true
regardless of which proposed extensions a build opts into.

An RFC is retired from this file the moment it is either accepted (the proto gains the field/RPC,
`agc_ext.h`'s function is promoted into the matching core header, its `agc_ext_` prefix if any is
dropped) or rejected (the function is deleted from `agc_ext.h`, not kept as dead code).

| RFC | Change | Status | `agc_ext.h` symbol |
|---|---|---|---|
| RFC-01 | Add `UpdateKeyState` to `KeyManagementService`. `KeyLifecycleState` has 8 values and no RPC moves between them; NIST SP 800-57 §7 is unimplementable without one. `reason` mandatory for a transition into `COMPROMISED`. | Proposed | `agc_ext_update_key_state` |
| RFC-02 | Add `format` and an optimistic-concurrency `version` to the policy messages (`CryptoPolicy`, `CreateCryptoPolicyRequest`, ...). | Proposed | *(message-shape change; no standalone function — see note below)* |
| RFC-03 | Add a per-message terminator to the four message-based streaming families (`bool end_of_message` on `EncryptMessageNext`/`DecryptMessageNext`/`SignMessageNext`/`VerifyMessageNext`, or split each into a `*MessageNextFinal`). **Without this the family supports exactly one message per session** (RECONCILIATION_PLAN.md §3.3), defeating the point of a message-based (vs. multi-part) API. | Proposed, high priority | *(deliberately not implemented in this commit — see note below)* |
| RFC-04 | Add `OperationMetadata metadata` to `DecryptInitRequest`, `DecryptMessageRequest`, `DecryptMessageBeginRequest`. | **Already implemented as DV-04** | — (in core, not `agc_ext.h`: these functions are unimplementable without it, so the divergence ships now rather than waiting) |
| RFC-05 | Add `bool remove_metadata` to `DeleteKeyRequest` (default `false` = retain in `DESTROYED` for audit, NIST SP 800-57 §8.3). | Proposed | *(no function needed: `agc_delete_key` always retains, matching the proposed default — nothing to add until the proto lets a caller opt out)* |
| RFC-06 | Add `string reason` to `RotateKeyRequest` for the audit trail. | Proposed | *(no function needed for the same reason as RFC-05: `agc_rotate_key` has nowhere on the wire to put a reason yet)* |
| RFC-07 | Add `buf.validate` bounds to `Xof.output_length_bytes` and `BatchEvaluatePolicyRequest.evaluations`. | **Already implemented locally as DV-10** | — (a local ceiling, not a wire change; this RFC asks for the wire-level bound too) |
| RFC-08 | Add `CRYPTO_ERROR_INVALID_KEY_STATE_TRANSITION` and `CRYPTO_ERROR_POLICY_VERSION_CONFLICT` — **only if** RFC-01 and RFC-02 land. | Blocked on RFC-01/02 | — |
| RFC-09 | Add `bytes key_check_value` to `ExportKeyResponse` (KMIP/PKCS#11 practice). | Proposed | — (would extend `agc_export_key`'s existing signature, not add a new one; deferred) |
| RFC-10 | Add `bytes key_attestation` to `ImportKeyRequest` for BYOK evidence. | Proposed | — (same shape as RFC-09: an added parameter, not a new function) |
| RFC-11 | Add a `WrapFormat format` echo to `WrapKeyResponse`. | Proposed | — (the caller already knows the format it requested; low priority) |
| RFC-12 | Deprecate `bool success` + `string message`, redundant with gRPC status (D4/DV-05). | Proposed | — |
| RFC-13 | Add MAC streaming (`GenerateMACInit/Update/Final`, `VerifyMACInit/Update/Final`). `MacScope.MAC_SCOPE_STREAMING` exists in the proto with no RPCs behind it — every other primitive with a streaming scope has the matching RPC family; MAC is the one gap. | **Implemented in `agc_ext.h`** | `agc_ext_generate_mac_init/_update/_final`, `agc_ext_verify_mac_init/_update/_final` |
| RFC-14 | Add `CancelOperation` to let a caller release a strayed session/provider state before its TTL. | **Implemented in `agc_ext.h`**, narrower than the original proposal | `agc_ext_cancel_operation` — see note below |
| RFC-15 | Consider unifying the six identical `(operation_id, data_chunk) -> bool` `*Update` RPCs. Raised, not resolved. | Raised only | — |

## Notes on what shipped in `agc_ext.h` and why

**RFC-01 (`agc_ext_update_key_state`)** is a straightforward addition: the internal key store
already tracks `agc_key_lifecycle_state` and already has an internal state-transition function
(`agc__keystore_update_state`, used since commit 7's `RotateKey`); this RFC only needed a public
entry point and the RFC's own mandatory-reason-for-COMPROMISED rule enforced at the boundary.

**RFC-13 (MAC streaming)** mirrors the existing multi-part digest family
(`agc_digest_init/update/final`) exactly: the stub backend has no real incremental MAC primitive
to expose (same honesty as every other stub construction in this tree), so Update accumulates
message bytes and Final computes the MAC once, over the whole accumulated message — this is a
real, working implementation of the RPC *shape* RFC-13 proposes, not a placeholder.

**RFC-14 (`agc_ext_cancel_operation`)** is narrower than a literal `CancelOperation` RPC would be:
`agc_session_cancel()` (core, commit 5) already lets a caller holding a session handle cancel it,
and `agc_session_attach()` (also commit 5, per D10) already lets a caller who only has the wire
`operation_id` string recover a handle. `agc_ext_cancel_operation(ctx, operation_id, reason)` is
pure convenience over those two existing calls — proposed anyway because a literal wire RPC would
still need *some* C entry point on the EMBEDDED/LOCAL side, and this is what it would look like.

**RFC-03 (`end_of_message` variants) was deliberately NOT implemented in this commit.** It is the
highest-priority RFC in this list (RECONCILIATION_PLAN.md calls it out as blocking a *usable*
message-based AEAD/sign family), but every candidate C shape for it either (a) adds a parameter to
an existing core function, which `agc_ext.h` cannot do without either duplicating four families'
worth of state machinery under new names or reaching into `stream.c`'s private
`agc_stream_state`/`stream_family` internals from a different translation unit, or (b) invents a
wire-invisible convention RECONCILIATION_PLAN.md §3.3 already warns against ("a parameter with no
wire representation is the worst kind to invent"). Shipping a half-considered shape here would
repeat exactly the mistake this reconciliation exists to fix. RFC-03 stays proposed-only until the
proto itself grows a real terminator, at which point it lands in core, not `agc_ext.h`.

**RFC-02/05/06/07/09/10/11/12** are recorded for completeness (they were raised during the original
comparison and reconciliation work) but have no `agc_ext.h` symbol: each either extends an
*existing* function's request shape (which `agc_ext.h` — additive by construction, per D16 — is
the wrong place for) or has already shipped as a local-only divergence (DV-04, DV-10). They remain
here as an honest record of ideas raised, not implemented, until the proto itself changes.
