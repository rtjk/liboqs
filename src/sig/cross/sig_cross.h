// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_CROSS_H
#define OQS_SIG_CROSS_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_cross_rsdp_128_balanced)
#define OQS_SIG_cross_rsdp_128_balanced_length_public_key 77
#define OQS_SIG_cross_rsdp_128_balanced_length_secret_key 32
#define OQS_SIG_cross_rsdp_128_balanced_length_signature 12912

OQS_SIG *OQS_SIG_cross_rsdp_128_balanced_new(void);
OQS_API OQS_STATUS OQS_SIG_cross_rsdp_128_balanced_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_cross_rsdp_128_balanced_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_cross_rsdp_128_balanced_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#endif
