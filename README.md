![logo](logo/logo.png)
# 
A high-performance one-to-many (1:N) fingerprint matching library for commodity hardware, written in modern platform-independent C++.

![Linux](https://github.com/neilharan/openafis/workflows/linux/badge.svg?branch=master)
![Windows](https://github.com/neilharan/openafis/workflows/windows/badge.svg?branch=master)
[![License: BSD-2-Clause](https://img.shields.io/github/license/neilharan/openafis.svg)](./LICENSE)
![C++ Standard](https://img.shields.io/badge/C%2B%2B-17%2F20-blue.svg)

Note: this library is focused on the matching problem. It does not currently extract minutiae from images.

The goal is to accurately identify one minutiae-set from 250K candidate sets within one second using modest laptop equipment. A secondary goal is to identify one minutiae-set from 1M candidate sets within one second, at a lower level of accuracy.

## Status

**Update 2020-11-12: goals have been exceeded @ 900K fp/s and 1.5M fp/s respectively (Linux x86_64 + clang 10). More optimizations, cache friendly tweaks, full vectorization and test tools to come.**

  | TASK | COMPLETE | NOTES |
  | ---- | -------- | ----- |
  | Template loading | 100% | |
  | Local matching | 100% | |
  | Global matching | 100% | |
  | CMake support | 90% | flto not yet working on MSVC + clang |
  | Test suite | 30% | EER, FMR100, FMR1000, ZeroFMR |
  | Benchmarks | 25% | |
  | Parallelization | 100% | |
  | Optimization | 50% | Cache friendly, false sharing, better triplet elimination |
  | Vectorizaton (SIMD) | 0% | AVX2, NEON |
  | Minutiae/pair rendering | 100% | SVG output |
  | Continuous integration setup | 0% | |
  | Certification/evaluation | 0% | FVC-onGoing, MINEX III (requires minutiae extraction feature) |

## Compiler support

All commits are automatically built with:

- gcc 10 (Linux)
- gcc 9 (Linux)
- gcc 8 (Linux)
- clang 10 (Linux)
- clang 11 (Linux)
- msvc 2017 (Windows win32 & x64)
- msvc 2019 (Windows win32 & x64)

clang-cl 11 (Windows x64) is also used during development.

## Getting started

#### Install dependencies

```sh
sudo apt install clang cmake llvm libpthread-stubs0-dev
```

#### Build & run

```sh
git clone https://github.com/neilharan/openafis.git
cd openafis
cmake . && make
cli/openafis-cli one-many --f1 fvc2002/DB1_B/101_2.iso --load-factor 4000 --path data/valid
```

This example loads the entire FVC2002 and FVC2004 datasets into memory 4000 times, randomly shuffles them in memory (to minimize any unfair advantages from caching/prefetching) then searches for the best match for the template fvc2002/DB1_B/101_2.iso.

As both probe and candidate templates exist in the same dataset you can expect a 100% match and a reference to the same disk file. If you now rename the template indicated by --f1 and execute the test a second time you can expect a 78% match to a different impression from the same individual.

## Algorithm

Improving Fingerprint Verification Using Minutiae Triplets (https://doi.org/10.3390/s120303418).

## Dependencies

- Delaunay 2D Triangulation (https://github.com/delfrrr/delaunator-cpp) [MIT License]

## Supported minutiae template formats

- ISO/IEC 19794-2:2005 (https://www.iso.org/standard/38746.html)
- CSV. For research and interchange purposes

## Test datasets

Tests and benchmarks are performed on freely available datasets from the Fingerprint Verification Competition hosted by the University of Bologna.

These data include several hundred reference fingerprints of varying quality:

- FVC2002 (http://bias.csr.unibo.it/fvc2002)
- FVC2004 (http://bias.csr.unibo.it/fvc2004)

The FVC archives are supplied in the tif raster format. A small python program [EXTRACT][] is provided to extract minutiae in ISO 19794-2:2005 format template files using SecuGens free SDK (https://secugen.com/products/sdk). Many fingerprint readers/SDKs can produce ISO format templates natively.

## Results

#### Minutiae and matched pair rendering

[![](results/fvc2002_db1_b_101_1.png)]()
[![](results/fvc2002_db1_b_101_7.png)]()

FVC2002 DB1_B 101_1 and 101_7 respectively. The implementation can reliably match displaced and rotated minutiae.

These images were produced using the libraries Render class. The class creates two SVG's identifying (a) all minutiae (grey circles and squares), (b) paired minutiae (circled blue), and (c) similarity scores of pairs. The SVG's were then overlayed on top of the original FVC images.

#### Efficacy

Preliminary M:M [RESULTS] matching FVC 2002/2004 data. Every impression is matched against every other impression.

TODO

## Example

```C++
#include "OpenAFIS.h"
...

TemplateISO19794_2_2005<uint32_t, Fingerprint> t1(1);
if (!t1.load("./fvc2002/DB1_B/101_1.iso")) {
    // Load error;
}
TemplateISO19794_2_2005<uint32_t, Fingerprint> t2(2);
if (!t2.load("./fvc2002/DB1_B/101_2.iso")) {
    // Load error;
}
MatchSimilarity match;
uint8_t s {};
match.compute(s, t1.fingerprints()[0], t2.fingerprints()[0]);
std::cout << "similarity = " << s;
```

## Benchmarking

TODO

#### x86-64

  | METRIC | THREADS | OPTIMIZATION | PRODUCTION/RESEARCH | RESULT |
  | ------ | ------- | ------------ | ------------------- | ------ |
  | Load time¹ | | CPU | Production |
  | Memory usage | | CPU | Production | |
  | Memory usage | | Memory | Production | |
  | Memory usage | | CPU | Research | |
  | 1:N match time | 1 | CPU | Production | |
  | 1:N match time | 4 | CPU | Production | |
  | 1:N match time | | Memory | Production | |

#### aarch64

  | METRIC | THREADS | OPTIMIZATION | PRODUCTION/RESEARCH | RESULT |
  | ------ | ------- | ------------ | ------------------- | ------ |
  | Load time¹ | | CPU | Production |
  | Memory usage | | CPU | Production | |
  | Memory usage | | Memory | Production | |
  | Memory usage | | CPU | Research | |
  | 1:N match time | 1 | CPU | Production | |
  | 1:N match time | 4 | CPU | Production | |
  | 1:N match time | | Memory | Production | |

¹ 19794-2:2005 templates pre-loaded in memory. The time taken to produce indexed in-memory structures is recorded (we're not measuring disk I/O here).

## Roadmap

- Minutiae extraction feature
- Research quaternion descriptors
- CUDA implementation
- Additional template readers (ANSI INCITS 378-2004/2009 and proprietary formats)
- Benchmark other libraries

## Licensing

OpenAFIS is licensed under the BSD 2-Clause License. See [LICENSE][] for the full license text.

[LICENSE]: https://github.com/neilharan/openafis/blob/master/LICENSE
[EXTRACT]: https://github.com/neilharan/openafis/blob/master/data/extract.py
[RESULTS]: https://github.com/neilharan/openafis/blob/master/results/fvs2002_2004_many_many.csv
