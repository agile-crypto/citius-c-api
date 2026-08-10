# Operation Params Split Plan

## Overview

`citius_operation_params_t` is currently a single mega tagged-union containing every
variant from every cryptographic scope (encryption, signing, KDF, key-wrapping, MAC).
This means a caller can legally place `hkdf_params` inside a `citius_encrypt_request_t`,
which the protobuf source (`operation_params.proto` + each message proto) makes impossible
through separate `oneof` fields per message.

The goal is to split `citius_operation_params_t` into **five scope-specific tagged unions**
that mirror the proto `oneof` families exactly, then update each message header to use the
correct narrower type instead of the shared mega-union.

The five proto oneof families are:

| C type (new)                       | Proto oneof variants                                                                                   | Used by                                           |
|------------------------------------|--------------------------------------------------------------------------------------------------------|---------------------------------------------------|
| `citius_encrypt_params_t`          | `NoParams`, `AeadEncryptParams`, `XtsEncryptParams`, `AsymmetricEncryptParams`, `VendorEncryptionParams` | encryption.proto — all 6 messages with scope_params |
| `citius_sign_params_t`             | `NoParams`, `SignatureDomainContext`, `VendorSignatureContext`                                          | signing.proto — all 8 messages with scope_params  |
| `citius_kdf_params_t`              | `HkdfOperationParams`, `Pbkdf2OperationParams`, `Argon2OperationParams`, `EcdhOperationParams`, `X942DhOperationParams`, `TlsPrfOperationParams`, `Tls12KdfOperationParams`, `Sp800108OperationParams`, `GostKdfOperationParams`, `X3dhOperationParams`, `VendorKdfParams` | key_derivation.proto — DeriveKeyRequest (kdf_params) |
| `citius_key_agreement_params_t`    | `EcdhOperationParams`, `X942DhOperationParams`, `X3dhOperationParams`, `VendorKdfParams`               | key_derivation.proto — KeyAgreementRequest (agreement_params) |
| `citius_wrap_params_t`             | `NoParams`, `KeyAgreementWrapParams`, `GostWrapOperationParams`, `VendorWrapParams`                    | key_wrapping.proto — WrapKeyRequest, UnwrapKeyRequest |
| `citius_mac_params_t`              | `NoParams`, `CustomizableMacParams`, `VendorMacParams`                                                 | mac.proto — GenerateMACRequest, VerifyMACRequest  |

The old `citius_operation_params_t` and `citius_op_params_type_t` are removed from
`citius_operation_params.h` once all message headers have been updated.

---

## Sub-Tasks

---

### Sub-Task 1 — Add the six scope-specific tagged unions to `citius_operation_params.h`

**Intent**  
Introduce the new narrow types alongside the existing mega-union so that Sub-Tasks 2–6
can be done independently without breaking anything during the transition.

**Expected Outcomes**  
- Six new `_type` enums and six new struct typedefs exist in the header.
- No existing code is changed; the file still compiles as before.
- Each new union carries exactly the variants listed in the table above.
- Each new type has a `CITIUS_*_NONE` / zero-init macro where applicable.

**Todo List**  
1. After the existing leaf-param structs (before the mega-union section), add:
   - `citius_encrypt_params_type_t` enum + `citius_encrypt_params_t` struct
   - `citius_sign_params_type_t` enum + `citius_sign_params_t` struct
   - `citius_kdf_params_type_t` enum + `citius_kdf_params_t` struct
   - `citius_key_agreement_params_type_t` enum + `citius_key_agreement_params_t` struct
   - `citius_wrap_params_type_t` enum + `citius_wrap_params_t` struct
   - `citius_mac_params_type_t` enum + `citius_mac_params_t` struct
2. Add a zero-init convenience macro for each new type.
3. Leave `citius_op_params_type_t` and `citius_operation_params_t` untouched for now.

**Relevant Context**  
- [`citius_operation_params.h`](citius-c-api/include/citius/types/citius_operation_params.h:360) — insert new types before line 327 (start of mega-union section)
- Proto source of truth: [`operation_params.proto`](api/proto/types/operation_params.proto)

**Status**: [ ] pending

---

### Sub-Task 2 — Update `citius_encryption.h` to use `citius_encrypt_params_t`

**Intent**  
Replace every `citius_operation_params_t scope_params` in the encryption message structs
with `citius_encrypt_params_t scope_params`, closing the type-safety hole.

**Expected Outcomes**  
- The six structs that carry `scope_params` in `citius_encryption.h` use the new type.
- The include of `citius_operation_params.h` is kept (it still defines the new type).
- The file-level comment block's field description is updated to name the new type.

**Todo List**  
1. Replace all six occurrences of `citius_operation_params_t scope_params` in
   `citius_encryption.h` with `citius_encrypt_params_t scope_params`.
2. Update the Doxygen / comment for the affected structs to list the valid arms.

**Relevant Context**  
- [`citius_encryption.h`](citius-c-api/include/citius/messages/citius_encryption.h:79)
- Affected structs: `citius_encrypt_request_t`, `citius_decrypt_request_t`,
  `citius_encrypt_init_request_t`, `citius_decrypt_init_request_t`,
  `citius_encrypt_message_init_request_t`, `citius_decrypt_message_init_request_t`

**Status**: [ ] pending

---

### Sub-Task 3 — Update `citius_signing.h` to use `citius_sign_params_t`

**Intent**  
Replace every `citius_operation_params_t scope_params` in the signing message structs.

**Expected Outcomes**  
- All eight signing request structs that carry `scope_params` use `citius_sign_params_t`.

**Todo List**  
1. Replace all occurrences of `citius_operation_params_t scope_params` in
   `citius_signing.h` with `citius_sign_params_t scope_params`.
2. Update comments listing valid arms.

**Relevant Context**  
- [`citius_signing.h`](citius-c-api/include/citius/messages/citius_signing.h)
- Lines 74, 92, 116, 136, 154, 187, 221, 281 per the grep results.

**Status**: [ ] pending

---

### Sub-Task 4 — Update `citius_key_derivation.h` to use the KDF and key-agreement types

**Intent**  
Replace `citius_operation_params_t kdf_params` with `citius_kdf_params_t` and
`citius_operation_params_t agreement_params` with `citius_key_agreement_params_t`.

**Expected Outcomes**  
- `citius_derive_key_request_t.kdf_params` is typed as `citius_kdf_params_t`.
- `citius_key_agreement_request_t.agreement_params` is typed as `citius_key_agreement_params_t`.

**Todo List**  
1. Replace `citius_operation_params_t kdf_params` with `citius_kdf_params_t kdf_params`.
2. Replace `citius_operation_params_t agreement_params` with
   `citius_key_agreement_params_t agreement_params`.
3. Update field comments.

**Relevant Context**  
- [`citius_key_derivation.h`](citius-c-api/include/citius/messages/citius_key_derivation.h:59)

**Status**: [ ] pending

---

### Sub-Task 5 — Update `citius_key_wrapping.h` to use `citius_wrap_params_t`

**Intent**  
Replace `citius_operation_params_t scope_params` in the two wrapping request structs.

**Expected Outcomes**  
- `citius_wrap_key_request_t.scope_params` and `citius_unwrap_key_request_t.scope_params`
  are typed as `citius_wrap_params_t`.

**Todo List**  
1. Replace both occurrences of `citius_operation_params_t scope_params` in
   `citius_key_wrapping.h` with `citius_wrap_params_t scope_params`.
2. Update field comments.

**Relevant Context**  
- [`citius_key_wrapping.h`](citius-c-api/include/citius/messages/citius_key_wrapping.h:47)

**Status**: [ ] pending

---

### Sub-Task 6 — Update `citius_mac.h` to use `citius_mac_params_t`

**Intent**  
Replace `citius_operation_params_t scope_params` in the two MAC request structs.

**Expected Outcomes**  
- `citius_generate_mac_request_t.scope_params` and `citius_verify_mac_request_t.scope_params`
  are typed as `citius_mac_params_t`.

**Todo List**  
1. Replace both occurrences of `citius_operation_params_t scope_params` in
   `citius_mac.h` with `citius_mac_params_t scope_params`.
2. Update the Doxygen comment listing valid enum values.

**Relevant Context**  
- [`citius_mac.h`](citius-c-api/include/citius/messages/citius_mac.h:41)

**Status**: [ ] pending

---

### Sub-Task 7 — Remove the old `citius_operation_params_t` mega-union

**Intent**  
Once all six message headers use the narrow types, the shared mega-union is dead code
and should be removed to prevent new callers from accidentally using it.

**Expected Outcomes**  
- `citius_op_params_type_t` enum is deleted from `citius_operation_params.h`.
- `citius_operation_params_t` struct is deleted.
- `CITIUS_OPERATION_PARAMS_NONE` macro is deleted.
- No other file in the repo still references `citius_operation_params_t`
  (verified by grep before deleting).

**Todo List**  
1. Grep the entire `citius-c-api/` tree for remaining uses of `citius_operation_params_t`.
2. Confirm zero remaining uses, then delete the three items from the header.
3. Remove the now-unused `CITIUS_OP_PARAMS_*` enum values and enum typedef.

**Relevant Context**  
- [`citius_operation_params.h`](citius-c-api/include/citius/types/citius_operation_params.h:327)

**Status**: [ ] pending
