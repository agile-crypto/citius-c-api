# Strengths and Weaknesses — `citius_*` vs `agc_*`

This is a plain-language summary of the two draft C APIs for the Citius cryptographic
service. For the full technical audit and line-by-line evidence, see
[`C_API_COMPARISON.md`](C_API_COMPARISON.md). For the plan to combine them, see
[`RECONCILIATION_PLAN.md`](RECONCILIATION_PLAN.md).

Both drafts try to do the same thing: let a C program call the Citius cryptographic
service (encrypt, sign, manage keys, etc.) as a normal function call, without needing
gRPC or protobuf, which don't support C directly. They take very different approaches to
the problem, and each one is good at what the other is bad at.

---

## The one-sentence version

**`citius_*` copies the network API's shape faithfully but forgets that C is not the
network** — it has no way to actually save or send the data it produces. **`agc_*`
behaves like a proper C library but its documentation makes claims about the network API
that are not true**, so you cannot trust it to match what the server actually does.

---

## `citius_*` — strengths

### It matches the specification field-for-field

Every message the server understands (`CreateKeyRequest`, `EncryptRequest`, and so on)
has a corresponding C struct with the same fields, in the same shape. If you know the
network API, you already know this one.

**Example:** the network request to create a key looks like this:

```
CreateKeyRequest {
  string name;
  string policy;
  ScopeSpecification scope_spec;
  optional string template_id;
  ...
}
```

The C version mirrors it directly:

```c
typedef struct {
    const char *name;
    const char *policy;
    citius_scope_specification_t scope_spec;
    const char *template_id;
    ...
} citius_create_key_request_t;
```

There is no guessing about what a field means or where it went.

### It actually builds and runs

This is not a small thing. `citius_*` compiles with CMake, links into a library, and
ships with a working test suite — 8 tests, all passing — plus three example programs
that demonstrate encrypting, signing, and managing keys. You can check out the code and
immediately see it work.

### It covers every operation the server offers

All 90 remote operations (encrypt, decrypt, sign, list keys, evaluate policy, and so on)
have a matching C function, and nothing was invented that doesn't exist on the server
side.

---

## `citius_*` — weaknesses

### It cannot actually save the result of an encryption

This is the most serious problem, and it breaks the whole point of the exercise.

When you encrypt something, the server generates a random value (a "nonce") that you
must save alongside the ciphertext — without it, nobody can ever decrypt the data again,
not even the same server. `citius_*` has no way to save this nonce to disk or a
database. It only holds a stack of raw pointers to memory that goes away the moment the
program that made the request exits.

**Example of the bug in its own example program:**

```c
dec_req.metadata = enc_resp.metadata;   /* comment says: MUST be stored + passed back */
```

The comment says the value "must be stored," but nothing in the library lets you turn it
into bytes you could write to a file. It's like being told to mail a letter with no
envelope.

### Zeroing out a request accidentally asks for weaker security

C programmers very commonly initialize a struct by zeroing it out
(`memset(&request, 0, sizeof(request))`). In `citius_*`, a zeroed-out security setting
means "this must NOT be true" rather than "I don't care." So a program that just wants
"any encryption key" ends up accidentally saying "give me a key that is explicitly not
FIPS-approved and not quantum-safe." The shipped example program has exactly this bug.

### It has two different error-numbering systems that disagree

`citius_*` invents its own error codes (like `2` for "key already exists") that use the
*same numbers* as the server's own error codes but mean *different things* (the server's
error `2` means "key expired"). If you tried to translate one system's errors into the
other, you'd get the wrong answer half the time.

### Adding a new field later would break every program that used the old version

There's no mechanism for the library to grow without forcing every program built against
it to be recompiled. The network API doesn't have this problem — you can add a new field
to a network message and old clients just ignore it. `citius_*` has no equivalent, so a
single new field added down the line is a breaking change for everyone.

### No safety net around passwords, keys, or verification results

There's no built-in way to securely erase a key from memory once you're done with it, no
constant-time comparison to avoid timing attacks, and no guarantee that a "was this
signature valid?" check can't be accidentally read before it's actually been set.

---

## `agc_*` — strengths

### It's genuinely designed like a real C library, not a network protocol wearing a C hat

Where `citius_*` copies the network shape, `agc_*` asks "what does a C program actually
need here?" and answers well:

- **You can switch where the crypto actually runs without changing your code.** A single
  setting decides whether operations happen locally in the same process, on the same
  machine over a socket, or over the network via gRPC. Every function behaves the same
  way in all three modes.
- **It solves the "must save the nonce" problem `citius_*` misses entirely.** It can turn
  the operation's metadata into the exact same bytes the server would send over the
  network, and back again — meaning a file encrypted by this C library can be decrypted
  by the actual server, and vice versa.
- **"I don't care" and "must be false" are properly distinguished**, so zeroing out a
  struct means "no special requirements," which is the safe default.
- **Verification results can't be misread.** If you check "is this signature valid?" and
  ignore the error code, you still can't accidentally treat a failed check as successful
  — the result is cleared to "invalid" before any work starts, and a failed check always
  also returns an error.
- **It plans for growing the library without breaking old programs**, the way the
  network API can add fields for free.
- **It gives you tools to actually protect sensitive data** — securely erasing memory,
  comparing secrets without leaking timing information, and locking sensitive memory
  pages so they can't be swapped to disk.

### Its design document explains *why*, not just *what*

Nearly every decision is written down with the reasoning behind it, which makes it much
easier to evaluate whether a choice was deliberate or accidental.

---

## `agc_*` — weaknesses

### Its documentation makes false claims about what the network API actually does

This is the central problem, and it undermines trust in everything else. The design
document says things about the network specification that are simply not true when you
check them against the actual specification.

**Example 1 — a made-up field:** the documentation says a certain streaming operation
takes a flag called `end_of_message` to mark the last chunk of data, and explains it as
if it were copied from the network spec. That field does not exist on the network side
at all — it was invented and then described as if it had been derived from the
specification.

**Example 2 — missing outputs:** the documentation claims a certain "finish" operation
"carries no output" — but the actual network specification says that operation *does*
return output (the finished ciphertext plus metadata). Four separate operations have this
same problem: real data the network side returns is silently thrown away.

**Example 3 — a wrong headline number:** the documentation says the library covers "all
98 operations." The actual count is 90. Eight of the "operations" it claims to cover
don't exist on the server at all — they were invented, then presented in a table
formatted exactly like the real ones, making them indistinguishable from the real
mapping without checking line by line.

### Its own vocabulary file breaks its own promised safety check

The file with all the numeric codes is labeled "GENERATED — DO NOT EDIT, checked
automatically in continuous integration to make sure it always matches the server." But
it contains two error codes that don't exist on the server side. If the promised
automatic check actually ran, it would fail immediately — which means either the check
was never built, or it was never run.

### It has no build system and has never been compiled into a working program

Where `citius_*` has a complete, passing test suite, `agc_*` is headers only. The header
files are syntactically valid C, but nothing has been built, linked, or executed. Whether
the design actually works in practice has not been demonstrated.

### Good ideas are hidden inside inaccurate claims

To be fair to `agc_*`, several of its "inventions" are genuinely good ideas — for
example, adding a way to cancel an in-progress operation, which the actual network API
is missing. The problem isn't that these ideas are bad; it's that they're presented as
if they already existed in the specification, rather than as proposed improvements to
suggest to the specification's maintainers.

---

## Side-by-side summary

| | `citius_*` | `agc_*` |
|---|---|---|
| Matches the network API's fields exactly | Yes | Mostly, but with several undocumented changes |
| Can actually save and restore results for later decryption | **No** | Yes |
| Zeroing a struct gives safe defaults | **No** | Yes |
| Can grow without breaking old programs | **No** | Yes |
| Compiles and has passing tests | **Yes** | No |
| Documentation can be trusted at face value | Mostly | **No — contains false claims** |
| Tools for erasing secrets / avoiding timing leaks | No | Yes |
| Works identically whether crypto runs locally or over the network | No | Yes |

---

## The takeaway

Neither draft is ready to ship on its own. `citius_*` is trustworthy but incomplete —
what it claims to do, it does correctly, but it's missing capabilities (like saving
results) that the whole system depends on. `agc_*` is complete in spirit and has the
right instincts for how a C library should behave, but its documentation cannot be taken
at face value, so every claim in it needs to be independently checked against the real
specification before it's relied upon.

The plan for combining them (see [`RECONCILIATION_PLAN.md`](RECONCILIATION_PLAN.md))
takes `agc_*`'s architecture — the parts that make it behave like a proper C library —
and rebuilds its content the way `citius_*` was built: derived directly and verifiably
from the real specification, field by field, with every deliberate difference written
down and checked by an automated test rather than left to a design document's prose.
