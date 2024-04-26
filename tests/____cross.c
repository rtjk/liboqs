#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#include <stdio.h>

////////
////////
static void print_array(const char *name, const uint8_t *array, size_t len) {
    printf("%s: ", name);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", array[i]);
    }
    printf("\n");
}
////////
////////

#define MESSAGE_LEN 50
//#define MESSAGE_LEN 30000

/* Cleaning up memory etc */
void cleanup_stack(uint8_t *secret_key, size_t secret_key_len);
void cleanup_heap(uint8_t *public_key, uint8_t *secret_key,
                  uint8_t *message, uint8_t *signature,
                  OQS_SIG *sig);


static OQS_STATUS example_stack(void) {

#ifdef OQS_ENABLE_SIG_cross_rsdp_256_fast

	OQS_STATUS rc;

	uint8_t public_key[OQS_SIG_cross_rsdp_256_fast_length_public_key];
	uint8_t secret_key[OQS_SIG_cross_rsdp_256_fast_length_secret_key];
	uint8_t message[MESSAGE_LEN];
	uint8_t signature[OQS_SIG_cross_rsdp_256_fast_length_signature];
	size_t message_len = MESSAGE_LEN;
	size_t signature_len;

	// let's create a random test message to sign
	OQS_randombytes(message, message_len);

	rc = OQS_SIG_cross_rsdp_256_fast_keypair(public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: keypair failed!\n");
		cleanup_stack(secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
		return OQS_ERROR;
	}
	else {
		printf("OK keypair\n");
	}


	rc = OQS_SIG_cross_rsdp_256_fast_sign(signature, &signature_len, message, message_len, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: sign failed!\n");
		cleanup_stack(secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
		return OQS_ERROR;
	}
	else {
		printf("OK sign\n");
	}


	rc = OQS_SIG_cross_rsdp_256_fast_verify(message, message_len, signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: verify failed!\n");
		cleanup_stack(secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
		return OQS_ERROR;
	}
	else {
		printf("OK verify\n");
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	uint8_t wrong_signature[OQS_SIG_cross_rsdp_256_fast_length_signature];
	OQS_randombytes(wrong_signature, OQS_SIG_cross_rsdp_256_fast_length_signature);
	rc = OQS_SIG_cross_rsdp_256_fast_verify(message, message_len, wrong_signature, signature_len, public_key);
	if (rc == OQS_SUCCESS) {
		fprintf(stderr, "ERROR: verify success with wrong signature!\n");
		cleanup_stack(secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
		return OQS_ERROR;
	}
	else {
		printf("OK verify fails with wrong signature\n");
	}
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	uint8_t wrong_public_key[OQS_SIG_cross_rsdp_256_fast_length_public_key];
	OQS_randombytes(wrong_public_key, OQS_SIG_cross_rsdp_256_fast_length_public_key);
	rc = OQS_SIG_cross_rsdp_256_fast_verify(message, message_len, signature, signature_len, wrong_public_key);
	if (rc == OQS_SUCCESS) {
		fprintf(stderr, "ERROR: verify success with wrong public key!\n");
		cleanup_stack(secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
		return OQS_ERROR;
	}
	else {
		printf("OK verify fails with wrong public key\n");
	}
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	uint8_t wrong_message[MESSAGE_LEN];
	OQS_randombytes(wrong_message, message_len);
	rc = OQS_SIG_cross_rsdp_256_fast_verify(wrong_message, message_len, signature, signature_len, public_key);
	if (rc == OQS_SUCCESS) {
		fprintf(stderr, "ERROR: verify success with wrong message!\n");
		cleanup_stack(secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
		return OQS_ERROR;
	}
	else {
		printf("OK verify fails with wrong message\n");
	}
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	////////
	////////
	printf("\n\n\n");
	print_array("message", message, message_len);
	printf("message_len: %zu\n", message_len);
	print_array("signature", signature, signature_len);
	printf("signature_len: %zu\n", signature_len);
	print_array("public_key", public_key, OQS_SIG_cross_rsdp_256_fast_length_public_key);
	printf("length_public_key: %zu\n", OQS_SIG_cross_rsdp_256_fast_length_public_key);
	print_array("secret_key", secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
	printf("length_secret_key: %zu\n", OQS_SIG_cross_rsdp_256_fast_length_secret_key);
	printf("\n\n\n");
	////////
	////////

	printf("[example_stack] OQS_SIG_cross_rsdp_256_fast operations completed.\n");
	cleanup_stack(secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
	return OQS_SUCCESS; // success!

#else

	printf("[example_stack] OQS_SIG_cross_rsdp_256_fast was not enabled at compile-time.\n");
	return OQS_SUCCESS;

#endif
}






static OQS_STATUS example_heap(void) {

#ifdef OQS_ENABLE_SIG_cross_rsdp_256_fast

	OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *message = NULL;
	uint8_t *signature = NULL;
	size_t message_len = MESSAGE_LEN;
	size_t signature_len;
	OQS_STATUS rc;

	sig = OQS_SIG_new(OQS_SIG_alg_cross_rsdp_256_fast);
	if (sig == NULL) {
		printf("[example_heap]  OQS_SIG_alg_cross_rsdp_256_fast was not enabled at compile-time.\n");
		return OQS_ERROR;
	}

	public_key = malloc(sig->length_public_key);
	secret_key = malloc(sig->length_secret_key);
	message = malloc(message_len);
	signature = malloc(sig->length_signature);
	if ((public_key == NULL) || (secret_key == NULL) || (message == NULL) || (signature == NULL)) {
		fprintf(stderr, "ERROR: malloc failed!\n");
		cleanup_heap(public_key, secret_key, message, signature, sig);
		return OQS_ERROR;
	}

	// let's create a random test message to sign
	OQS_randombytes(message, message_len);

	rc = OQS_SIG_keypair(sig, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_keypair failed!\n");
		cleanup_heap(public_key, secret_key, message, signature, sig);
		return OQS_ERROR;
	}
	rc = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_sign failed!\n");
		cleanup_heap(public_key, secret_key, message, signature, sig);
		return OQS_ERROR;
	}
	rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify failed!\n");
		cleanup_heap(public_key, secret_key, message, signature, sig);
		return OQS_ERROR;
	}

	printf("[example_heap]  OQS_SIG_cross_rsdp_256_fast operations completed.\n");
	cleanup_heap(public_key, secret_key, message, signature, sig);
	return OQS_SUCCESS; // success
#else

	printf("[example_heap] OQS_SIG_cross_rsdp_256_fast was not enabled at compile-time.\n");
	return OQS_SUCCESS;

#endif
}

int main(void) {
	OQS_init();
	if (example_stack() == OQS_SUCCESS && example_heap() == OQS_SUCCESS) {
		OQS_destroy();
		return EXIT_SUCCESS;
	} else {
		OQS_destroy();
		return EXIT_FAILURE;
	}
}

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
}

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key,
                  uint8_t *message, uint8_t *signature,
                  OQS_SIG *sig) {
	if (sig != NULL) {
		OQS_MEM_secure_free(secret_key, sig->length_secret_key);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(message);
	OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
}
