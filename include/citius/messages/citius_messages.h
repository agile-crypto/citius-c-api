/**
 * @file citius_messages.h  (messages/ aggregate)
 * @brief Aggregates all message headers under include/citius/messages/.
 *
 * Pull in every request/response pair with a single include:
 *
 *   #include "citius/messages/citius_messages.h"
 *
 * Individual headers can also be included directly for fine-grained
 * dependency control.
 *
 * Include order mirrors the proto dependency graph:
 *   metadata (leaf) → key_management → encryption, signing, mac, digest,
 *   random, key_derivation, key_encapsulation, key_wrapping, policy
 */

#ifndef CITIUS_MESSAGES_ALL_H
#define CITIUS_MESSAGES_ALL_H

#include "citius/messages/citius_metadata.h"
#include "citius/messages/citius_key_management.h"
#include "citius/messages/citius_encryption.h"
#include "citius/messages/citius_signing.h"
#include "citius/messages/citius_mac.h"
#include "citius/messages/citius_digest.h"
#include "citius/messages/citius_random.h"
#include "citius/messages/citius_key_derivation.h"
#include "citius/messages/citius_key_encapsulation.h"
#include "citius/messages/citius_key_wrapping.h"
#include "citius/messages/citius_policy.h"

#endif /* CITIUS_MESSAGES_ALL_H */
