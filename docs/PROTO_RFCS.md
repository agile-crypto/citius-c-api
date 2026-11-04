# Proto RFCs

Fifteen proposed changes to `github.com/agile-crypto/api`, found while reconciling this C binding
against the real wire specification (see `RECONCILIATION_PLAN.md` §5 for the original list, §9.3
for the discussion of why RFC-04 in particular is not optional). Each RFC that has a corresponding
C function today has it in `include/agc/agc_ext.h`, gated behind `AGC_ENABLE_PROPOSED_EXTENSIONS`
and excluded from Tier 1b/1c conformance (D16): the core's "exactly the proto's RPCs" claim must stay true
regardless of which proposed extensions a build opts into.

RFC-01 to RFC-06, RFC-08 to RFC-10, RFC-13 and RFC-14 were accepted into
the proto with api v0.3.0 and are retired from this file; the C functions
RFC-01, -13 and -14 had in `agc_ext.h` were promoted into the core headers.

An RFC is retired from this file the moment it is either accepted (the proto gains the field/RPC,
`agc_ext.h`'s function is promoted into the matching core header, its `agc_ext_` prefix if any is
dropped) or rejected (the function is deleted from `agc_ext.h`, not kept as dead code).

| RFC | Change | Status | `agc_ext.h` symbol |
|---|---|---|---|
| RFC-07 | Add a `buf.validate` bound to `BatchEvaluatePolicyRequest.evaluations` (`Xof.output_length_bytes` gained one in api v0.3.0). | **Already implemented locally as DV-10** | — (a local ceiling, not a wire change) |
| RFC-11 | Add a `WrapFormat format` echo to `WrapKeyResponse`. | Proposed | — (the caller already knows the format it requested; low priority) |
| RFC-12 | Deprecate `bool success` + `string message`, redundant with gRPC status (D4/DV-05). | Proposed | — |
| RFC-15 | Consider unifying the six identical `(operation_id, data_chunk) -> bool` `*Update` RPCs. Raised, not resolved. | Raised only | — |

## Notes on the open RFCs

**RFC-07, -11 and -12** are wire hygiene: none needs a C function, so
`agc_ext.h` has no symbol for them. RFC-12 is applied in C regardless, as
D4: `success` and `message` collapse into `agc_rc` and `agc_last_error`.

**RFC-15** is raised, not resolved: unifying the identical `*Update` RPCs
would change every streaming family's wire shape, and the C side already
gives them one signature each.
