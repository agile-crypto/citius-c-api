/**
 * @file citius_services.h
 * @brief Aggregate include for all Citius service interface headers.
 *
 * Including this single header gives access to all seven service interfaces,
 * matching the structure of api/proto/services/:
 *
 *   citius_crypto_service.h          ← crypto_service.proto
 *   citius_key_management_service.h  ← key_management_service.proto
 *   citius_key_establishment_service.h ← key_establishment_service.proto
 *   citius_streaming_crypto_service.h ← streaming_crypto_service.proto
 *   citius_crypto_policy_service.h   ← crypto_policy_service.proto
 *   citius_discovery_service.h       ← discovery_service.proto
 *   citius_provider_service.h        ← provider_service.proto
 *
 * Alternatively, include only the service headers you need to reduce
 * compilation dependencies.
 *
 * All seven headers are also included transitively by citius/citius.h.
 */

#ifndef CITIUS_SERVICES_H
#define CITIUS_SERVICES_H

#include "citius/services/citius_crypto_service.h"
#include "citius/services/citius_key_management_service.h"
#include "citius/services/citius_key_establishment_service.h"
#include "citius/services/citius_streaming_crypto_service.h"
#include "citius/services/citius_crypto_policy_service.h"
#include "citius/services/citius_discovery_service.h"
#include "citius/services/citius_provider_service.h"

#endif /* CITIUS_SERVICES_H */
