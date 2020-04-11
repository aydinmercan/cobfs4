#include "cobfs4.h"
#include "test.h"

int main(void) {
#if 1
    test_elligator();
#else
    test_hmac();
    test_ecdh();
    test_ntor();
    test_handshake();
    test_aead();
    test_frame();
    test_seeded_random();
    test_siphash();
    test_stream();
#endif
    return 0;
}
