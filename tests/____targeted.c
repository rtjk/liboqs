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
static void read_array(const char *filename, uint8_t *array, size_t len) {
    FILE *file = fopen(filename, "r"); // Open the file for reading
    if (file == NULL) {
        perror("Error opening file");
        return;
    }
    for (size_t i = 0; i < len; i++) {
        int byte;
        if (fscanf(file, "%2x", &byte) == 1) { // Read two characters at a time
            array[i] = (uint8_t)byte; // Convert the read value to uint8_t
        } else {
            // If fscanf fails, handle the error or break the loop
            fprintf(stderr, "Error reading byte at index %zu\n", i);
            break;
        }
    }
    fclose(file); // Close the file after reading
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

	printf("\n\nAVX2 %d\n\n", OQS_CPU_has_extension(OQS_CPU_EXT_AVX2));

	read_array("0_pk.txt", public_key, OQS_SIG_cross_rsdp_256_fast_length_public_key);
	read_array("0_sk.txt", secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
	read_array("0_m.txt", message, MESSAGE_LEN);

	rc = OQS_SIG_cross_rsdp_256_fast_sign(signature, &signature_len, message, message_len, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: sign failed!\n");
		cleanup_stack(secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
		return OQS_ERROR;
	}
	else {
		printf("\n\nOK sign\n");
	}

	rc = OQS_SIG_cross_rsdp_256_fast_verify(message, message_len, signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: verify failed!\n");
		cleanup_stack(secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
		return OQS_ERROR;
	}
	else {
		printf("\n\nOK verify\n");
	}

	////////
	////////
	printf("\n\n\n");
	print_array("message", message, message_len);
	printf("message_len: %zu\n", message_len);
	print_array("signature [FIRST 20]", signature, 20);
	printf("signature_len: %zu\n", signature_len);
	print_array("public_key [FIRST 20]", public_key, 20);
	printf("length_public_key: %zu\n", OQS_SIG_cross_rsdp_256_fast_length_public_key);
	print_array("secret_key", secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
	printf("length_secret_key: %zu\n", OQS_SIG_cross_rsdp_256_fast_length_secret_key);
	printf("\n\n\n");
	////////
	////////

	printf("[example_stack] operations completed.\n");
	cleanup_stack(secret_key, OQS_SIG_cross_rsdp_256_fast_length_secret_key);
	return OQS_SUCCESS; // success!

#else

	printf("[example_stack] was not enabled at compile-time.\n");
	return OQS_SUCCESS;

#endif
}

int main(void) {
	OQS_init();
	if (example_stack() == OQS_SUCCESS) {
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

