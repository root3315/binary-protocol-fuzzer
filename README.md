# Binary Protocol Fuzzer

A coverage-guided binary protocol fuzzer for discovering security vulnerabilities and crashes in binary protocol implementations.

## Overview

This fuzzer targets binary protocols by generating mutated inputs based on seed data. It uses multiple mutation strategies to explore the input space efficiently and detect crashes, hangs, and assertion failures in protocol parsers.

### Key Features

- **Multiple mutation strategies**: Bit flips, byte operations, integer overflows, block shuffling, and more
- **Weighted strategy selection**: Configurable mutation weights to focus on effective strategies
- **Crash deduplication**: Unique crash detection using hash-based signatures
- **Deterministic mode**: Reproducible fuzzing campaigns with fixed seeds
- **Protocol-aware parsing**: Built-in support for common binary protocol structures
- **Coverage tracking**: Monitors input lengths, magic bytes, and message types seen

## Installation

### Prerequisites

- CMake 3.14 or later
- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- POSIX threads library

### Build Instructions

```bash
# Clone or navigate to the project directory
cd binary-protocol-fuzzer

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build
cmake --build .

# Run tests
ctest

# Install (optional)
sudo cmake --install .
```

### Build with Sanitizers (Recommended for Development)

```bash
cmake -DENABLE_SANITIZERS=ON ..
cmake --build .
```

This enables AddressSanitizer and UndefinedBehaviorSanitizer to catch memory errors and undefined behavior during fuzzing.

## Usage

### Basic Usage

```bash
# Run with default settings (100,000 iterations)
./fuzzer

# Run with a seed file
./fuzzer -s seed_input.bin -n 1000000

# Run for a specific duration
./fuzzer -d 60 -o crashes/

# Verbose output
./fuzzer -v -n 50000
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-s, --seed FILE` | Load seed input from file |
| `-n, --iterations N` | Run N iterations (default: 100000) |
| `-t, --timeout MS` | Set timeout in milliseconds (default: 100) |
| `-d, --duration SEC` | Run for specified duration in seconds |
| `-o, --output DIR` | Output directory for crash files |
| `-v, --verbose` | Enable verbose output |
| `--seed-value N` | Use specific random seed for reproducibility |

### Examples

```bash
# Quick test run
./fuzzer -n 1000 -v

# Extended fuzzing campaign with crash output
./fuzzer -s protocol_seed.bin -d 3600 -o output/ -v

# Reproducible run with fixed seed
./fuzzer --seed-value 42 -n 100000
```

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BinaryProtocolFuzzer                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Corpus    │  │  Mutator    │  │  Process Callback   │  │
│  │  (Seeds)    │──│  (Strateg-  │──│  (Target Parser)    │  │
│  │             │  │   ies)      │  │                     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│         │                │                      │            │
│         │                │                      ▼            │
│         │                │            ┌─────────────────┐    │
│         │                └────────────│  Crash Detector │    │
│         │                             │  & Deduplicator │    │
│         ▼                             └─────────────────┘    │
│  ┌─────────────┐                                              │
│  │  Coverage   │                                              │
│  │  Tracker    │                                              │
│  └─────────────┘                                              │
└─────────────────────────────────────────────────────────────┘
```

### Mutation Strategies

The fuzzer employs multiple mutation strategies, each targeting different vulnerability classes:

| Strategy | Description | Vulnerability Class |
|----------|-------------|---------------------|
| BIT_FLIP | Flip individual bits | Boolean/flag handling bugs |
| BYTE_FLIP | Replace byte with random value | General corruption |
| BYTE_INSERT | Insert random byte | Off-by-one, buffer issues |
| BYTE_DELETE | Remove byte | Bounds checking |
| BYTE_DUPLICATE | Duplicate existing byte | Parsing state bugs |
| INTEGER_OVERFLOW | Write max integer values | Integer overflow |
| INTEGER_UNDERFLOW | Write zero/min values | Integer underflow |
| MAGIC_VALUE | Insert 0x00, 0xFF, etc. | Edge case handling |
| BLOCK_SHUFFLE | Swap data blocks | Ordering dependencies |
| ARITHMETIC | Add/subtract small values | Boundary conditions |
| INTERESTING_VALUE | Insert known problematic values | Common bug patterns |

### Protocol Format

The built-in protocol parser expects messages with this structure:

```
┌─────────┬──────────┬─────────┬───────────┬───────────┐
│  Magic  │   Type   │ Length  │ Sequence  │ Checksum  │
│ 1 byte  │ 1 byte   │ 2 bytes │ 4 bytes   │ 2 bytes   │
└─────────┴──────────┴─────────┴───────────┴───────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │     Payload     │
                    │  (variable)     │
                    └─────────────────┘
```

**Message Types:**
- `0x01` - HANDSHAKE
- `0x02` - DATA
- `0x03` - ACK
- `0x04` - ERROR
- `0x05` - CONTROL
- `0x06` - HEARTBEAT
- `0x07` - DISCONNECT

### Creating Seed Inputs

Good seed inputs improve fuzzing efficiency. Create seeds that represent valid protocol messages:

```cpp
#include "protocol.h"

protocol::ProtocolConfig config;
config.magic_byte = 0xAA;
config.little_endian = true;

// Generate a valid handshake message
std::vector<uint8_t> seed = protocol::generate_valid_message(
    protocol::MessageType::HANDSHAKE,
    {0x01, 0x00},  // Version payload
    1,             // Sequence number
    config
);

// Save to file for later use
std::ofstream out("seed.bin", std::ios::binary);
out.write(reinterpret_cast<char*>(seed.data()), seed.size());
```

## Integration

### Using as a Library

The fuzzer can be integrated into your project:

```cpp
#include "fuzzer.h"
#include "protocol.h"

int main() {
    // Configure fuzzer
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.timeout_us = 100000;  // 100ms
    
    fuzzer::BinaryProtocolFuzzer fuzzer(config);
    
    // Set up protocol
    protocol::ProtocolConfig proto_config;
    proto_config.magic_byte = 0xAA;
    fuzzer.set_protocol_config(proto_config);
    
    // Add seed inputs
    fuzzer.add_seed_input({0xAA, 0x02, 0x00, 0x00});
    
    // Set process callback (your parser)
    fuzzer.set_process_callback([](const std::vector<uint8_t>& data) {
        // Your protocol parsing logic here
        // Return false to indicate crash/failure
        return my_parser(data.data(), data.size());
    });
    
    // Set crash callback
    fuzzer.set_crash_callback([](const fuzzer::FuzzResult& result) {
        std::cout << "Crash found! Size: " << result.input_size << "\n";
    });
    
    // Run fuzzer
    uint64_t crashes = fuzzer.run(1000000);
    
    return crashes > 0 ? 1 : 0;
}
```

## Project Structure

```
binary-protocol-fuzzer/
├── CMakeLists.txt          # Build configuration
├── README.md               # This file
├── cmake/
│   └── config.h.in         # Version header template
├── src/
│   ├── main.cpp            # Main entry point and demo processor
│   ├── fuzzer.h            # Fuzzer class declaration
│   ├── fuzzer.cpp          # Fuzzer implementation
│   ├── protocol.h          # Protocol definitions
│   └── protocol.cpp        # Protocol parsing utilities
└── tests/
    └── test_fuzzer.cpp     # Unit tests
```

## Testing

Run the test suite:

```bash
cd build
ctest --verbose
```

Or run tests directly:

```bash
./test_fuzzer
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Fuzzing completed, no crashes found |
| 1 | Error (invalid arguments, missing files, etc.) |
| 2 | Fuzzing completed, crashes found |

## Tips for Effective Fuzzing

1. **Use diverse seeds**: Multiple seed inputs covering different message types improve coverage
2. **Enable sanitizers**: Build with sanitizers to catch memory corruption bugs
3. **Start small**: Begin with short runs to verify setup before long campaigns
4. **Monitor coverage**: Use verbose mode to track which message types are being exercised
5. **Save crashes**: Always specify an output directory to preserve crash inputs for analysis

## License

This project is provided as-is for educational and security research purposes.
