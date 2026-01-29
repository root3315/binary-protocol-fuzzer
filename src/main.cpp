#include "fuzzer.h"
#include "protocol.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <csignal>
#include <atomic>
#include <cstring>

// Global fuzzer pointer for signal handler
static fuzzer::BinaryProtocolFuzzer* g_fuzzer = nullptr;
static std::atomic<bool> g_interrupted(false);

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    (void)signum;
    g_interrupted.store(true);
    if (g_fuzzer) {
        g_fuzzer->stop();
    }
}

// Demo protocol processor that simulates parsing binary data
// In real usage, this would be replaced with actual protocol implementation
class DemoProtocolProcessor {
public:
    DemoProtocolProcessor()
        : messages_processed_(0)
        , bytes_processed_(0) {}

    // Process a fuzzed input and return true if successful
    // This simulates what a real protocol parser would do
    bool process(const std::vector<uint8_t>& data) {
        if (data.empty()) {
            return false;
        }

        bytes_processed_ += data.size();

        // Use detailed parsing with proper error handling
        protocol::ProtocolConfig config;
        config.magic_byte = 0xAA;
        config.min_header_size = 10;
        config.max_payload_size = 4096;
        config.requires_checksum = false;
        config.little_endian = true;

        protocol::ParseResult result = protocol::parse_message_detailed(
            data.data(), data.size(), config);

        if (result.result != protocol::ValidationResult::OK) {
            // Log validation errors for debugging
            if (result.result != protocol::ValidationResult::ERROR_INSUFFICIENT_DATA &&
                result.result != protocol::ValidationResult::ERROR_INVALID_MAGIC) {
                // Only process non-trivial errors
                handle_validation_error(result);
            }
            return result.result == protocol::ValidationResult::OK;
        }

        // Process valid message based on type
        switch (result.message.header.type) {
            case protocol::MessageType::HANDSHAKE:
                return process_handshake(result.message);
            case protocol::MessageType::DATA:
                return process_data(result.message);
            case protocol::MessageType::ACK:
                return process_ack(result.message);
            case protocol::MessageType::ERROR:
                return process_error(result.message);
            case protocol::MessageType::CONTROL:
                return process_control(result.message);
            case protocol::MessageType::HEARTBEAT:
                return process_heartbeat(result.message);
            case protocol::MessageType::DISCONNECT:
                return process_disconnect(result.message);
            default:
                return process_unknown_type(result.message);
        }
    }

    size_t get_messages_processed() const { return messages_processed_; }
    size_t get_bytes_processed() const { return bytes_processed_; }

private:
    size_t messages_processed_;
    size_t bytes_processed_;

    void handle_validation_error(const protocol::ParseResult& result) {
        // Centralized error handling for validation failures
        (void)result;
        // In production, this would log to a structured log system
        messages_processed_++;
    }

    bool process_handshake(const protocol::ParsedMessage& msg) {
        if (msg.payload.size() < 2) return false;

        // Extract version field
        uint8_t version = msg.payload[0];

        // Version 0 or 255 might trigger edge cases
        if (version == 0 || version == 255) {
            return false;
        }

        messages_processed_++;
        return true;
    }

    bool process_data(const protocol::ParsedMessage& msg) {
        if (msg.payload.empty()) return false;

        // Extract flags
        uint8_t flags = msg.payload[0];

        // Check for compression flag
        if (flags & 0x01) {
            // Would decompress here - common vulnerability area
            return true;
        }

        // Check for encryption flag
        if (flags & 0x02) {
            // Would decrypt here
            return true;
        }

        messages_processed_++;
        return true;
    }

    bool process_ack(const protocol::ParsedMessage& msg) {
        if (msg.payload.size() < 4) return false;

        // Extract sequence number being acknowledged
        uint32_t ack_seq = msg.payload[0] | (msg.payload[1] << 8) |
                          (msg.payload[2] << 16) | (msg.payload[3] << 24);

        (void)ack_seq;
        messages_processed_++;
        return true;
    }

    bool process_error(const protocol::ParsedMessage& msg) {
        if (msg.payload.empty()) return false;

        uint8_t error_code = msg.payload[0];

        // Error code 0 might be invalid
        if (error_code == 0) {
            return false;
        }

        messages_processed_++;
        return true;
    }

    bool process_control(const protocol::ParsedMessage& msg) {
        if (msg.payload.empty()) return false;

        uint8_t control_type = msg.payload[0];

        switch (control_type) {
            case 0x01:  // Reset
            case 0x02:  // Pause
            case 0x03:  // Resume
                messages_processed_++;
                return true;
            default:
                return false;
        }
    }

    bool process_heartbeat(const protocol::ParsedMessage& msg) {
        (void)msg;
        messages_processed_++;
        return true;
    }

    bool process_disconnect(const protocol::ParsedMessage& msg) {
        if (msg.payload.empty()) return false;

        uint8_t reason = msg.payload[0];
        (void)reason;

        messages_processed_++;
        return true;
    }

    bool process_unknown_type(const protocol::ParsedMessage& msg) {
        (void)msg;
        messages_processed_++;
        return false;  // Reject unknown types
    }
};

void print_usage(const char* program) {
    std::cout << "Binary Protocol Fuzzer\n";
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help           Show this help message\n";
    std::cout << "  -s, --seed FILE      Load seed input from file\n";
    std::cout << "  -n, --iterations N   Run N iterations (default: 100000)\n";
    std::cout << "  -t, --timeout MS     Set timeout in milliseconds (default: 100)\n";
    std::cout << "  -d, --duration SEC   Run for specified duration in seconds\n";
    std::cout << "  -o, --output DIR     Output directory for crashes\n";
    std::cout << "  -v, --verbose        Enable verbose output\n";
    std::cout << "  --seed-value N       Use specific random seed\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program << " -s seed.bin -n 1000000\n";
    std::cout << "  " << program << " -d 60 -o crashes/\n";
}

void print_stats(const fuzzer::FuzzStats& stats, bool verbose) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - stats.start_time).count();

    std::cout << "\n=== Fuzzing Statistics ===\n";
    std::cout << "Total inputs:      " << stats.total_inputs << "\n";
    std::cout << "Crashes found:     " << stats.crashes_found << "\n";
    std::cout << "Unique crashes:    " << stats.unique_crashes << "\n";
    std::cout << "Hangs found:       " << stats.hangs_found << "\n";
    std::cout << "Bytes fuzzed:      " << stats.bytes_fuzzed << "\n";
    std::cout << "Avg exec time:     " << std::fixed << std::setprecision(3)
              << stats.avg_execution_time_ms << " ms\n";

    if (elapsed > 0) {
        std::cout << "Execs/sec:         " << (stats.total_inputs / elapsed) << "\n";
    }

    if (verbose) {
        std::cout << "\nCoverage:\n";
        std::cout << "  Lengths seen:    " << stats.covered_lengths.size() << "\n";
        std::cout << "  Magic bytes:     " << stats.covered_magic_bytes.size() << "\n";
        std::cout << "  Message types:   " << stats.covered_message_types.size() << "\n";
    }

    std::cout << "Elapsed time:      " << elapsed << " seconds\n";
}

int main(int argc, char* argv[]) {
    // Parse command line arguments
    std::string seed_file;
    std::string output_dir;
    uint64_t iterations = 100000;
    uint64_t timeout_ms = 100;
    double duration = 0.0;
    bool verbose = false;
    unsigned int seed_value = 0;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if ((arg == "-s" || arg == "--seed") && i + 1 < argc) {
            seed_file = argv[++i];
        } else if ((arg == "-n" || arg == "--iterations") && i + 1 < argc) {
            iterations = std::stoull(argv[++i]);
        } else if ((arg == "-t" || arg == "--timeout") && i + 1 < argc) {
            timeout_ms = std::stoull(argv[++i]);
        } else if ((arg == "-d" || arg == "--duration") && i + 1 < argc) {
            duration = std::stod(argv[++i]);
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg == "--seed-value" && i + 1 < argc) {
            seed_value = static_cast<unsigned int>(std::stoul(argv[++i]));
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Set up signal handlers for graceful shutdown
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Configure the fuzzer
    fuzzer::FuzzerConfig config;
    config.timeout_us = timeout_ms * 1000;
    config.seed = seed_value;
    config.deterministic = (seed_value != 0);

    // Create fuzzer instance
    fuzzer::BinaryProtocolFuzzer fuzzer(config);
    g_fuzzer = &fuzzer;

    // Configure protocol
    protocol::ProtocolConfig proto_config;
    proto_config.magic_byte = 0xAA;
    proto_config.min_header_size = 10;
    proto_config.max_payload_size = 4096;
    proto_config.requires_checksum = false;
    proto_config.little_endian = true;

    fuzzer.set_protocol_config(proto_config);

    // Create demo processor
    DemoProtocolProcessor processor;

    // Set up process callback
    fuzzer.set_process_callback([&processor](const std::vector<uint8_t>& data) {
        return processor.process(data);
    });

    // Set up crash callback
    fuzzer.set_crash_callback([&output_dir, verbose](const fuzzer::FuzzResult& result) {
        if (verbose) {
            std::cout << "\n[CRASH] Input size: " << result.input_size
                      << " Error: " << result.error_message << "\n";
        }

        if (!output_dir.empty()) {
            std::ostringstream filename;
            filename << output_dir << "/crash_" << std::hex
                     << fuzzer::data_hash(result.input).substr(0, 8) << ".bin";
            fuzzer::write_crash_file(filename.str(), result.input);

            if (verbose) {
                std::cout << "  Saved to: " << filename.str() << "\n";
            }
        }
    });

    // Load seed file if provided
    if (!seed_file.empty()) {
        if (!fuzzer.load_seed_file(seed_file)) {
            std::cerr << "Failed to load seed file: " << seed_file << "\n";
            return 1;
        }
        if (verbose) {
            std::cout << "Loaded seed from: " << seed_file << "\n";
        }
    } else {
        // Generate default seed inputs if none provided
        // Create valid protocol messages as starting points
        std::vector<uint8_t> handshake = protocol::generate_valid_message(
            protocol::MessageType::HANDSHAKE,
            {0x01, 0x00},  // Version 1.0
            1,
            proto_config
        );
        fuzzer.add_seed_input(handshake);

        std::vector<uint8_t> data_msg = protocol::generate_valid_message(
            protocol::MessageType::DATA,
            {0x00, 0x00, 0x00, 0x00},  // Empty payload marker
            2,
            proto_config
        );
        fuzzer.add_seed_input(data_msg);

        // Also add some raw bytes for diversity
        fuzzer.add_seed_input({0xAA, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00});

        if (verbose) {
            std::cout << "Generated default seed inputs\n";
        }
    }

    std::cout << "Binary Protocol Fuzzer starting...\n";
    std::cout << "Iterations: " << iterations << "\n";
    if (duration > 0) {
        std::cout << "Duration: " << duration << " seconds\n";
    }
    std::cout << "Timeout: " << timeout_ms << " ms\n";
    std::cout << "Seed: " << (seed_value != 0 ? std::to_string(seed_value) : "random") << "\n";
    std::cout << "\nPress Ctrl+C to stop\n";

    // Run the fuzzer
    uint64_t crashes = 0;
    if (duration > 0) {
        crashes = fuzzer.run_duration(duration);
    } else {
        crashes = fuzzer.run(iterations);
    }

    // Print final statistics
    print_stats(fuzzer.get_stats(), verbose);

    std::cout << "\nFuzzing complete.\n";
    std::cout << "Messages processed by demo: " << processor.get_messages_processed() << "\n";
    std::cout << "Bytes processed by demo: " << processor.get_bytes_processed() << "\n";

    if (crashes > 0) {
        std::cout << "\n*** Found " << crashes << " crash(es) ***\n";
        return 2;  // Non-zero exit to indicate crashes found
    }

    return 0;
}
