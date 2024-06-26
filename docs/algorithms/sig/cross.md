# CROSS

- **Algorithm type**: Digital signature scheme.
- **Main cryptographic assumption**: hardness of the restricted syndrome decoding problem for random linear codes on a finite field.
- **Principal submitters**: TODO.
- **Auxiliary submitters**: TODO.
- **Authors' website**: https://www.cross-crypto.com/
- **Specification version**: 2.1.
- **Primary Source**<a name="primary-source"></a>:
  - **Source**: https://github.com/rtjk/CROSS-PQClean/commit/08e605c0dcc34d1af4c146052825bb4b44d69070
  - **Implementation license (SPDX-Identifier)**: TODO


## Parameter set summary

|      Parameter set       | Parameter set alias   | Security model   |   Claimed NIST Level |   Public key size (bytes) |   Secret key size (bytes) |   Signature size (bytes) |
|:------------------------:|:----------------------|:-----------------|---------------------:|--------------------------:|--------------------------:|-------------------------:|
| cross-rsdp-128-balanced  | NA                    | EUF-CMA          |                    1 |                        77 |                        32 |                    12912 |
|   cross-rsdp-128-fast    | NA                    | EUF-CMA          |                    1 |                        77 |                        32 |                    19152 |
|   cross-rsdp-128-small   | NA                    | EUF-CMA          |                    1 |                        77 |                        32 |                    10080 |
| cross-rsdp-192-balanced  | NA                    | EUF-CMA          |                    3 |                       115 |                        48 |                    28222 |
|   cross-rsdp-192-fast    | NA                    | EUF-CMA          |                    3 |                       115 |                        48 |                    42682 |
|   cross-rsdp-192-small   | NA                    | EUF-CMA          |                    3 |                       115 |                        48 |                    23642 |
| cross-rsdp-256-balanced  | NA                    | EUF-CMA          |                    5 |                       153 |                        64 |                    51056 |
|   cross-rsdp-256-fast    | NA                    | EUF-CMA          |                    5 |                       153 |                        64 |                    76298 |
|   cross-rsdp-256-small   | NA                    | EUF-CMA          |                    5 |                       153 |                        64 |                    43592 |
| cross-rsdpg-128-balanced | NA                    | EUF-CMA          |                    1 |                        54 |                        32 |                     9236 |
|   cross-rsdpg-128-fast   | NA                    | EUF-CMA          |                    1 |                        54 |                        32 |                    12472 |
|  cross-rsdpg-128-small   | NA                    | EUF-CMA          |                    1 |                        54 |                        32 |                     7956 |
| cross-rsdpg-192-balanced | NA                    | EUF-CMA          |                    3 |                        83 |                        48 |                    23380 |
|   cross-rsdpg-192-fast   | NA                    | EUF-CMA          |                    3 |                        83 |                        48 |                    27404 |
|  cross-rsdpg-192-small   | NA                    | EUF-CMA          |                    3 |                        83 |                        48 |                    18188 |
| cross-rsdpg-256-balanced | NA                    | EUF-CMA          |                    5 |                       106 |                        64 |                    40134 |
|   cross-rsdpg-256-fast   | NA                    | EUF-CMA          |                    5 |                       106 |                        64 |                    48938 |
|  cross-rsdpg-256-small   | NA                    | EUF-CMA          |                    5 |                       106 |                        64 |                    32742 |

## cross-rsdp-128-balanced implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?‡   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:----------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                 |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                 |

Are implementations chosen based on runtime CPU feature detection? **No**.

 ‡For an explanation of what this denotes, consult the [Explanation of Terms](#explanation-of-terms) section at the end of this file.

## cross-rsdp-128-fast implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdp-128-small implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdp-192-balanced implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdp-192-fast implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdp-192-small implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdp-256-balanced implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdp-256-fast implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdp-256-small implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdpg-128-balanced implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdpg-128-fast implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdpg-128-small implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdpg-192-balanced implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdpg-192-fast implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdpg-192-small implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdpg-256-balanced implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdpg-256-fast implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## cross-rsdpg-256-small implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | clean                    | All                         | All                             | None                    | False                              | False                                          | False                |
| [Primary Source](#primary-source) | avx2                     | x86\_64                     | All                             | AVX2                    | False                              | False                                          | False                |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## Explanation of Terms

- **Large Stack Usage**: Implementations identified as having such may cause failures when running in threads or in constrained environments.