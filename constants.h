#ifndef COBFS4_CONSTANTS
#define COBFS4_CONSTANTS

#define COBFS4_MAX_HANDSHAKE_SIZE 8192
#define COBFS4_HMAC_LEN 32
#define COBFS4_HASH_LEN 32
#define COBFS4_TAG_LEN 16
#define COBFS4_ELLIGATOR_LEN 32
#define COBFS4_AUTH_LEN 32
#define COBFS4_SEED_LEN 32
#define COBFS4_PUBKEY_LEN 32
#define COBFS4_INLINE_SEED_FRAME_LEN 45
#define COBFS4_SERVER_HANDSHAKE_LEN 96
#define COBFS4_SERVER_MIN_PAD_LEN COBFS4_INLINE_SEED_FRAME_LEN
#define COBFS4_SERVER_MAX_PAD_LEN 8096
#define COBFS4_CLIENT_HANDSHAKE_LEN 64
#define COBFS4_CLIENT_MIN_PAD_LEN 85
#define COBFS4_CLIENT_MAX_PAD_LEN 8128

//Oh no, this will make my code break on January 29 2084
#define COBFS4_EPOCH_HOUR_LEN 6

#endif
