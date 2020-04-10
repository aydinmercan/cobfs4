#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "cobfs4.h"
#include "elligator.h"
#include "test.h"
#include "constants.h"

#if 0
/*
 * The following test vectors were written by
 * Yawning Angel for libelligator
 */
struct TestVectors {
    bool valid;
    uint8_t pub[32];
    uint8_t repr[32];
    uint8_t priv[32];
};

const struct TestVectors vectors[] = {
    {
        .valid = true,
        .pub = { 0x11, 0x95, 0x3b, 0xb6, 0x26, 0x8b, 0x92, 0xa2, 0xae, 0x97, 0xbe, 0x71, 0x9d, 0xcf, 0x7d, 0x2d, 0xb8, 0x64, 0x32, 0x0f, 0x80, 0xc2, 0x06, 0x7c, 0xa8, 0xc1, 0xd6, 0x49, 0x3d, 0xca, 0x20, 0x11,  },
        .repr = { 0xe6, 0x1a, 0x1a, 0x7a, 0xb0, 0xb7, 0xba, 0x28, 0xa7, 0x43, 0xfc, 0x01, 0x10, 0x82, 0x70, 0x5a, 0x8a, 0x32, 0xac, 0xcc, 0xc0, 0x02, 0xf9, 0xed, 0x8d, 0xef, 0x87, 0x43, 0x75, 0x0e, 0xd9, 0x0e,  },
        .priv = { 0xa8, 0x0d, 0xcd, 0xfa, 0xf4, 0xa3, 0x3b, 0x5f, 0xda, 0x02, 0xec, 0xdf, 0xc1, 0x7c, 0xc0, 0x16, 0xdc, 0xd7, 0xf9, 0xc7, 0x0d, 0xfd, 0xc8, 0x84, 0xa6, 0x0e, 0x33, 0x1b, 0xd3, 0xbd, 0x3f, 0x7f,  }
    },
    {
        .valid = true,
        .pub = { 0xad, 0x8f, 0x77, 0x2a, 0xc6, 0x27, 0x40, 0x19, 0x6b, 0xfd, 0x0b, 0x00, 0xe6, 0x1d, 0x4f, 0xbb, 0x7b, 0x61, 0x64, 0xfc, 0xfa, 0x9b, 0x9b, 0xaa, 0x99, 0x12, 0xdc, 0x35, 0xf8, 0x20, 0xcb, 0x3c,  },
        .repr = { 0x7c, 0xfb, 0x14, 0xfa, 0xb7, 0x2d, 0x23, 0x21, 0x53, 0xfa, 0x55, 0x8c, 0x10, 0x29, 0xc5, 0xcb, 0x12, 0x14, 0x2d, 0x34, 0xb4, 0xf3, 0x54, 0xc0, 0xc1, 0x50, 0x6e, 0x96, 0x25, 0x73, 0x79, 0x2e,  },
        .priv = { 0x28, 0x57, 0x2c, 0x0e, 0xdb, 0x0b, 0x76, 0xf2, 0x54, 0x21, 0x45, 0x5d, 0xdb, 0x77, 0x8c, 0x79, 0x05, 0x13, 0xfd, 0x54, 0x29, 0xb6, 0x1f, 0xce, 0x83, 0x25, 0x0d, 0xfe, 0xfa, 0x04, 0x83, 0x45,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0xe0, 0xc7, 0x38, 0x0b, 0x24, 0xc2, 0xc4, 0x5e, 0xc7, 0x91, 0x8f, 0x9e, 0xe8, 0xa5, 0x33, 0x1c, 0xa0, 0xb0, 0xd0, 0xa1, 0xd1, 0xe8, 0x37, 0x84, 0x23, 0x8c, 0xdf, 0xb2, 0x4f, 0x12, 0xa7, 0x62,  }
    },
    {
        .valid = true,
        .pub = { 0x09, 0xef, 0x7b, 0xb3, 0x50, 0xfc, 0x8b, 0xc3, 0x09, 0x58, 0x11, 0xa5, 0x48, 0x78, 0xef, 0x18, 0x3d, 0x44, 0xcb, 0xfc, 0x23, 0x37, 0x34, 0xda, 0xef, 0xcd, 0x48, 0x96, 0x98, 0xef, 0x6a, 0x05,  },
        .repr = { 0x45, 0xcc, 0xe7, 0xed, 0xf5, 0x88, 0xdd, 0xda, 0xfb, 0x09, 0xdf, 0x3d, 0x2d, 0xfe, 0x4f, 0x3c, 0xca, 0x36, 0x07, 0x50, 0xdd, 0x2f, 0xe7, 0x76, 0xc9, 0x47, 0x2f, 0x0d, 0xbc, 0xa6, 0x0b, 0x20,  },
        .priv = { 0x80, 0x80, 0xff, 0x43, 0x54, 0x0a, 0xf3, 0x79, 0x14, 0xf0, 0xf1, 0x87, 0x4f, 0xeb, 0x00, 0x83, 0x6b, 0x03, 0xf4, 0x78, 0x9f, 0x4c, 0x0a, 0xbf, 0xcd, 0x2e, 0xff, 0x9c, 0x10, 0xe4, 0x3c, 0x64,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0xb0, 0x22, 0x90, 0x32, 0x2f, 0x40, 0x00, 0x83, 0x91, 0x5d, 0x3d, 0x6b, 0x26, 0x74, 0x78, 0x5e, 0x91, 0xe5, 0x06, 0xb4, 0x6c, 0x34, 0x4c, 0x08, 0xbb, 0xf9, 0x54, 0x90, 0x49, 0x32, 0xc5, 0x44,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0xb0, 0xfd, 0xa1, 0x8f, 0x60, 0x53, 0xf2, 0x4a, 0x7e, 0x05, 0x2c, 0xbf, 0x58, 0x83, 0x6e, 0xa3, 0x23, 0x3e, 0x79, 0x87, 0xc3, 0x8c, 0xcb, 0x80, 0x2d, 0xde, 0x4c, 0x8c, 0x77, 0x90, 0x41, 0x4b,  }
    },
    {
        .valid = true,
        .pub = { 0x18, 0x44, 0xaf, 0x5a, 0x11, 0xbc, 0xa9, 0xf4, 0xa6, 0xa1, 0xf8, 0x9e, 0x8c, 0x24, 0x11, 0x0c, 0x0b, 0x4a, 0xf4, 0x22, 0x15, 0xc2, 0x67, 0x0c, 0x68, 0x66, 0x03, 0xd2, 0x50, 0x44, 0x3f, 0x26,  },
        .repr = { 0xd9, 0xa2, 0xfc, 0xfd, 0x5b, 0xbb, 0x2b, 0x6d, 0x83, 0x21, 0xd2, 0xc2, 0xe0, 0x2f, 0xc0, 0x28, 0x74, 0x1e, 0xa7, 0x01, 0x94, 0xfa, 0xb8, 0xd2, 0x53, 0xd5, 0x31, 0xe3, 0xe7, 0xe5, 0x7f, 0x08,  },
        .priv = { 0x00, 0xab, 0xc9, 0x71, 0xb5, 0x37, 0xe6, 0x84, 0xd8, 0x22, 0x90, 0x4e, 0x26, 0x84, 0x53, 0xe1, 0x91, 0xec, 0x17, 0x6e, 0xa1, 0xb7, 0x0d, 0xb3, 0x5b, 0x37, 0x03, 0xb4, 0x52, 0x38, 0x53, 0x41,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0x08, 0x38, 0x73, 0x29, 0x43, 0xbb, 0xad, 0xa2, 0x84, 0x40, 0xda, 0x27, 0x42, 0xc4, 0x05, 0x95, 0xd0, 0x7d, 0x47, 0x76, 0x87, 0x8f, 0xc5, 0xa9, 0x42, 0xfa, 0xea, 0x77, 0x42, 0x9d, 0x2d, 0x62,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0x70, 0x6d, 0x2c, 0x88, 0x78, 0x1b, 0x60, 0x80, 0x8a, 0xaf, 0x82, 0x98, 0xde, 0xfe, 0x19, 0x54, 0xcc, 0x11, 0x2f, 0x50, 0x50, 0x8c, 0x81, 0xfe, 0xed, 0x64, 0xdb, 0x66, 0x39, 0xcc, 0x1c, 0x7a,  }
    },
    {
        .valid = true,
        .pub = { 0xd8, 0x8b, 0x32, 0xdc, 0xf1, 0x98, 0x2e, 0x3e, 0x11, 0x99, 0xe7, 0x5c, 0x0b, 0x78, 0x6f, 0x4e, 0xec, 0x11, 0xbb, 0x55, 0xcb, 0x64, 0xce, 0xc5, 0x03, 0xcd, 0x70, 0xea, 0x95, 0x9f, 0x8a, 0x10,  },
        .repr = { 0x47, 0x54, 0xd8, 0xf2, 0xfd, 0xa9, 0xe3, 0xb3, 0xa5, 0xc2, 0x86, 0xc5, 0x36, 0x87, 0x7e, 0x45, 0x68, 0x57, 0xde, 0xf4, 0xd5, 0xfb, 0x49, 0xfc, 0xbf, 0x6f, 0x2f, 0x81, 0xf9, 0xe8, 0xd9, 0x23,  },
        .priv = { 0x60, 0xe4, 0x7b, 0x67, 0x61, 0xda, 0xa7, 0x81, 0xce, 0x2b, 0xc6, 0xd6, 0xca, 0xd6, 0x41, 0x35, 0xc8, 0x80, 0x46, 0x4d, 0x74, 0x4d, 0xfb, 0x6b, 0x83, 0xe4, 0xac, 0x9b, 0xf1, 0xb6, 0xbd, 0x7f,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0x28, 0xae, 0x07, 0xef, 0x5f, 0xe0, 0x1c, 0xd5, 0x4c, 0x69, 0xd1, 0xdc, 0xa1, 0x14, 0xad, 0x6c, 0x86, 0xbf, 0x52, 0x7a, 0x8b, 0xcb, 0xfe, 0xf0, 0x68, 0x9a, 0x83, 0xd8, 0x6f, 0x36, 0xac, 0x74,  }
    },
    {
        .valid = true,
        .pub = { 0x71, 0x27, 0x7e, 0xf1, 0xc6, 0xb9, 0x5e, 0xc5, 0xe1, 0xcb, 0xea, 0xba, 0x8f, 0x3d, 0x57, 0xf4, 0x87, 0x8c, 0x5e, 0xd1, 0x59, 0xdd, 0x9c, 0xfa, 0xb6, 0x21, 0x73, 0xfd, 0x15, 0x94, 0xd1, 0x70,  },
        .repr = { 0x82, 0xd1, 0x70, 0xac, 0x60, 0x92, 0x83, 0x7a, 0xb7, 0xab, 0x55, 0x44, 0x40, 0x51, 0xce, 0xa0, 0x56, 0xc9, 0x35, 0x45, 0x3f, 0x3f, 0xae, 0x74, 0xdf, 0xca, 0x2d, 0x5d, 0x97, 0x37, 0xa1, 0x1b,  },
        .priv = { 0x40, 0xda, 0x08, 0x13, 0xd0, 0xd7, 0xe9, 0xbb, 0xe8, 0xc4, 0x4c, 0xad, 0x8d, 0xec, 0x81, 0x5c, 0xa0, 0x40, 0x4a, 0xfd, 0xff, 0xe5, 0x4d, 0x57, 0x5e, 0x3f, 0x05, 0x0a, 0x98, 0xc4, 0x50, 0x79,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0x40, 0x60, 0xca, 0x06, 0x86, 0xc6, 0x5d, 0xa9, 0x01, 0xf8, 0xdc, 0xb6, 0x3c, 0x2a, 0x28, 0x95, 0x39, 0x10, 0x54, 0x1a, 0x31, 0x60, 0x04, 0x69, 0x9d, 0x61, 0xd2, 0x24, 0x0d, 0x6e, 0xdb, 0x5f,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0x28, 0x5f, 0xcd, 0x92, 0xec, 0xbe, 0x3e, 0x58, 0xa0, 0xa9, 0xa0, 0x74, 0x5e, 0x3d, 0x2e, 0xce, 0x8f, 0xe7, 0x41, 0xc7, 0xc8, 0x52, 0x88, 0xc7, 0x2c, 0x17, 0x32, 0x70, 0x5a, 0x55, 0xe0, 0x5a,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0x68, 0x6b, 0x89, 0x7f, 0xbf, 0x61, 0x3d, 0x88, 0x81, 0x82, 0x73, 0x83, 0x68, 0xff, 0x30, 0x3d, 0xd4, 0x06, 0x76, 0x93, 0x06, 0xcf, 0x2f, 0x4f, 0x7c, 0x1c, 0x84, 0x40, 0xef, 0x68, 0x1f, 0x5a,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0x60, 0x17, 0x34, 0x90, 0xc7, 0x76, 0x79, 0x13, 0x9a, 0x5d, 0xc7, 0xaf, 0xa7, 0xbd, 0x56, 0x24, 0xfc, 0xa6, 0x51, 0xca, 0xae, 0x4e, 0x06, 0x91, 0xcb, 0x07, 0xb9, 0x06, 0x4e, 0xa3, 0xde, 0x7f,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0x98, 0x14, 0xc3, 0x73, 0x86, 0x67, 0x34, 0x6e, 0xe9, 0xd5, 0xf7, 0xc2, 0x60, 0x71, 0xe6, 0x72, 0x07, 0xce, 0x1c, 0x9a, 0xc8, 0x98, 0xd3, 0xc2, 0x01, 0x89, 0xb6, 0xaa, 0x73, 0xed, 0x70, 0x74,  }
    },
    {
        .valid = true,
        .pub = { 0x9a, 0x43, 0x23, 0xe3, 0x12, 0xe8, 0x8e, 0x6d, 0x6c, 0xc8, 0xc9, 0x4b, 0x3e, 0xc7, 0x6e, 0xed, 0x7d, 0x56, 0x6c, 0x3c, 0x8a, 0xd6, 0xf5, 0x03, 0x55, 0x6f, 0xb6, 0x11, 0x8e, 0xa8, 0x53, 0x12,  },
        .repr = { 0x58, 0xb2, 0x75, 0xe2, 0xbe, 0xfc, 0xfe, 0xdd, 0xfc, 0x36, 0xc3, 0x7d, 0x8e, 0xca, 0xe5, 0xaa, 0x27, 0x76, 0x60, 0xcb, 0x52, 0x92, 0xba, 0xc2, 0x6e, 0xa9, 0xf2, 0x95, 0x4e, 0x78, 0x08, 0x24,  },
        .priv = { 0xf0, 0xae, 0xb3, 0xcf, 0x6f, 0xf5, 0xc8, 0xdc, 0xf6, 0x74, 0xe7, 0x14, 0xdc, 0xfc, 0x29, 0xeb, 0x5f, 0x76, 0x89, 0x58, 0x14, 0x6c, 0x13, 0x89, 0xa7, 0x9f, 0x8a, 0x60, 0x6e, 0x99, 0x2c, 0x79,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0xd0, 0xbc, 0xdc, 0xef, 0x6e, 0xd6, 0x6a, 0xe4, 0xf9, 0x5a, 0x45, 0x20, 0x1f, 0x13, 0x6f, 0xbc, 0x86, 0x51, 0xcd, 0xf9, 0xad, 0xc7, 0xa5, 0x81, 0x7c, 0x55, 0x87, 0x89, 0x06, 0x38, 0x33, 0x5b,  }
    },
    {
        .valid = false,
        .pub = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .repr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  },
        .priv = { 0xe0, 0x2e, 0xd2, 0x9b, 0x82, 0x9b, 0xd4, 0x1d, 0xa9, 0x47, 0x92, 0x40, 0xfe, 0x5a, 0x51, 0xe7, 0xa3, 0xdf, 0x2e, 0x57, 0x7e, 0x77, 0x9a, 0x1d, 0x01, 0x8c, 0x63, 0x6d, 0xd4, 0x6b, 0x4b, 0x7e,  }
    },
};
#endif

void test_elligator(void) {
    EVP_PKEY *init_pubkey_obj;
    EVP_PKEY *res_pubkey_obj;
    uint8_t init_pubkey[32];
    uint8_t res_pubkey[32];
    int count = 0;
    int good = 0;
    int bad = 0;
    int invalid = 0;
    uint8_t elligator[COBFS4_ELLIGATOR_LEN];
    enum cobfs4_return_code rc;
    size_t key_len = COBFS4_PUBKEY_LEN;

#if 1
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    EVP_PKEY_keygen_init(pctx);
    init_pubkey_obj = EVP_PKEY_new();

    for (count = 0; count < TEST_CASE_COUNT; ++count) {
        EVP_PKEY_keygen(pctx, &init_pubkey_obj);

        EVP_PKEY_get_raw_public_key(init_pubkey_obj, init_pubkey, &key_len);

        rc = elligator2(init_pubkey_obj, elligator);
        if (rc == COBFS4_OK) {
            res_pubkey_obj = elligator2_inv(elligator);
            if (res_pubkey_obj) {
                EVP_PKEY_get_raw_public_key(res_pubkey_obj, res_pubkey, &key_len);
                if (memcmp(init_pubkey, res_pubkey, 32) == 0) {
                    ++good;
                } else {
                    ++bad;
                }
                EVP_PKEY_free(res_pubkey_obj);
            }
        } else {
            ++invalid;
        }
    }
    EVP_PKEY_free(init_pubkey_obj);

    EVP_PKEY_CTX_free(pctx);

    printf("Elligator test ran %d times\nResults:\nGood: %d\nBad: %d\nInvalid: %d\n", count, good, bad, invalid);

    memset(elligator, 0, sizeof(elligator));
    res_pubkey_obj = elligator2_inv(elligator);
    if (res_pubkey_obj) {
        EVP_PKEY_get_raw_public_key(res_pubkey_obj, res_pubkey, &key_len);

        int res = 0;
        for (int i = 0; i < 32; ++i) {
            if (elligator[i] != 0x00) {
                printf("All zero elligator input Bad!\n");
                res = 1;
                break;
            }
        }
        if (res == 0) {
            printf("All zero elligator input Good!\n");
        }
        EVP_PKEY_free(res_pubkey_obj);
    }

    good = 0;
    bad = 0;

    for (count = 0; count < TEST_CASE_COUNT; ++count) {
        RAND_bytes(elligator, sizeof(elligator));
        res_pubkey_obj = elligator2_inv(elligator);
        if (res_pubkey_obj) {
            ++good;
            EVP_PKEY_free(res_pubkey_obj);
            continue;
        } else {
            ++bad;
            continue;
        }
    }
    printf("Elligator inverse only test ran %d times\nResults:\nGood: %d\nBad: %d\n", count, good, bad);

    good = 0;
    bad = 0;
#else

    for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); ++i) {
        memcpy(init_pubkey, vectors[i].pub, sizeof(init_pubkey));
        init_pubkey_obj = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, init_pubkey, sizeof(init_pubkey));

        rc = elligator2(init_pubkey_obj, elligator);
        if (vectors[i].valid && rc != COBFS4_OK) {
            ++bad;
            EVP_PKEY_free(init_pubkey_obj);
            continue;
        } else if (vectors[i].valid == false && rc != COBFS4_ERROR) {
            ++bad;
            EVP_PKEY_free(init_pubkey_obj);
            continue;
        }

        for (int j = 0; j < 16; ++j) {
            uint8_t tmp = elligator[j];
            elligator[j] = elligator[31-j];
            elligator[31-j] = tmp;
        }
        if (memcmp(elligator, vectors[i].repr, sizeof(elligator)) != 0) {
            ++bad;
            EVP_PKEY_free(init_pubkey_obj);
            continue;
        }

        for (int j = 0; j < 16; ++j) {
            uint8_t tmp = elligator[j];
            elligator[j] = elligator[31-j];
            elligator[31-j] = tmp;
        }
        res_pubkey_obj = elligator2_inv(elligator);
        if (res_pubkey_obj) {
            EVP_PKEY_get_raw_public_key(res_pubkey_obj, res_pubkey, &(size_t){32});
            if (memcmp(init_pubkey, res_pubkey, 32) == 0) {
                ++good;
            } else {
                ++bad;
            }
            //This shouldn't be necessary, but I'll do it explicitly for sanity's sake
            if (memcmp(res_pubkey, vectors[i].pub, 32) == 0) {
                ++good;
            } else {
                ++bad;
            }
            EVP_PKEY_free(res_pubkey_obj);
            EVP_PKEY_free(init_pubkey_obj);
        } else {
            ++bad;
            EVP_PKEY_free(init_pubkey_obj);
            continue;
        }
    }

    printf("Elligator test vectors ran %d times\nResults:\nGood: %d\nBad: %d\n", count, good, bad);
#endif
}
