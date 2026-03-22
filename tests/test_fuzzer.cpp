#include "fuzzer.h"
#include "protocol.h"
#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <string>

// Simple test framework macros
#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "Running " << #name << "... "; \
    try { \
        test_##name(); \
        std::cout << "PASSED\n"; \
        passed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << "\n"; \
        failed++; \
    } catch (...) { \
        std::cout << "FAILED: Unknown exception\n"; \
        failed++; \
    } \
} while(0)

#define ASSERT_TRUE(x) do { if (!(x)) throw std::runtime_error("Assertion failed: " #x); } while(0)
#define ASSERT_FALSE(x) do { if (x) throw std::runtime_error("Assertion failed: !" #x); } while(0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) throw std::runtime_error("Assertion failed: " #a " == " #b); } while(0)
#define ASSERT_NE(a, b) do { if ((a) == (b)) throw std::runtime_error("Assertion failed: " #a " != " #b); } while(0)
#define ASSERT_GE(a, b) do { if ((a) < (b)) throw std::runtime_error("Assertion failed: " #a " >= " #b); } while(0)
#define ASSERT_LE(a, b) do { if ((a) > (b)) throw std::runtime_error("Assertion failed: " #a " <= " #b); } while(0)

// Test counters
static int passed = 0;
static int failed = 0;

// ============================================================================
// CRC16 Tests
// ============================================================================

TEST(crc16_basic) {
    // Empty data should return initial value
    uint8_t* empty = nullptr;
    uint16_t crc = protocol::calculate_crc16(empty, 0);
    ASSERT_EQ(crc, 0xFFFF);
}

TEST(crc16_single_byte) {
    // Single byte test
    uint8_t data[] = {0x00};
    uint16_t crc = protocol::calculate_crc16(data, 1);
    // CRC of single zero byte
    ASSERT_NE(crc, 0);
}

TEST(crc16_known_value) {
    // Test against known CRC value
    // "123456789" should produce 0x29B1 with CRC-16/CCITT
    const char* test_str = "123456789";
    uint16_t crc = protocol::calculate_crc16(
        reinterpret_cast<const uint8_t*>(test_str),
        9
    );
    ASSERT_EQ(crc, 0x29B1);
}

TEST(crc16_consistency) {
    // Same data should produce same CRC
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint16_t crc1 = protocol::calculate_crc16(data, 4);
    uint16_t crc2 = protocol::calculate_crc16(data, 4);
    ASSERT_EQ(crc1, crc2);
}

TEST(crc16_different_data) {
    // Different data should produce different CRC (usually)
    uint8_t data1[] = {0x00, 0x00, 0x00, 0x00};
    uint8_t data2[] = {0xFF, 0xFF, 0xFF, 0xFF};
    uint16_t crc1 = protocol::calculate_crc16(data1, 4);
    uint16_t crc2 = protocol::calculate_crc16(data2, 4);
    ASSERT_NE(crc1, crc2);
}

TEST(crc16_incremental) {
    // CRC should be incremental (streaming)
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    uint16_t crc_full = protocol::calculate_crc16(data, 4);
    
    // Calculate with first byte only
    uint16_t crc1 = protocol::calculate_crc16(data, 1);
    
    // Full CRC should differ from partial (different data lengths)
    ASSERT_NE(crc_full, crc1);
}

// ============================================================================
// Protocol Message Tests
// ============================================================================

TEST(protocol_generate_valid_message) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = true;
    config.requires_checksum = false;

    std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04};
    auto message = protocol::generate_valid_message(
        protocol::MessageType::DATA,
        payload,
        12345,
        config
    );

    // Check minimum size (header = 10 bytes + payload)
    ASSERT_TRUE(message.size() >= 10);
    ASSERT_EQ(message.size(), 10 + payload.size());

    // Check magic byte
    ASSERT_EQ(message[0], 0xAA);

    // Check message type
    ASSERT_EQ(message[1], static_cast<uint8_t>(protocol::MessageType::DATA));
}

TEST(protocol_parse_valid_message) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = true;
    config.requires_checksum = false;

    // Generate a valid message
    std::vector<uint8_t> payload = {0x10, 0x20, 0x30};
    auto raw = protocol::generate_valid_message(
        protocol::MessageType::HANDSHAKE,
        payload,
        1,
        config
    );

    // Parse it back
    auto parsed = protocol::parse_message(raw.data(), raw.size(), config);

    ASSERT_TRUE(parsed.has_value());
    ASSERT_TRUE(parsed->valid);
    ASSERT_EQ(parsed->header.magic, 0xAA);
    ASSERT_EQ(parsed->header.type, protocol::MessageType::HANDSHAKE);
    ASSERT_EQ(parsed->payload.size(), payload.size());
}

TEST(protocol_parse_invalid_magic) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;

    // Create message with wrong magic byte
    std::vector<uint8_t> invalid = {0xBB, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    auto parsed = protocol::parse_message(invalid.data(), invalid.size(), config);

    ASSERT_TRUE(parsed.has_value());
    ASSERT_FALSE(parsed->valid);
}

TEST(protocol_parse_truncated) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.min_header_size = 10;

    // Too short message
    std::vector<uint8_t> short_msg = {0xAA, 0x02};

    auto parsed = protocol::parse_message(short_msg.data(), short_msg.size(), config);

    // Should return nullopt for too-short messages
    ASSERT_FALSE(parsed.has_value());
}

TEST(protocol_parse_length_overflow) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.max_payload_size = 100;
    config.little_endian = true;

    // Message claims huge payload but doesn't have it
    std::vector<uint8_t> msg = {
        0xAA,                    // magic
        0x02,                    // type = DATA
        0xFF, 0xFF,              // length = 65535 (too big)
        0x00, 0x00, 0x00, 0x00,  // sequence
        0x00, 0x00               // checksum
    };

    auto parsed = protocol::parse_message(msg.data(), msg.size(), config);

    ASSERT_TRUE(parsed.has_value());
    ASSERT_FALSE(parsed->valid);
}

TEST(protocol_message_type_string) {
    ASSERT_EQ(protocol::message_type_to_string(protocol::MessageType::HANDSHAKE), "HANDSHAKE");
    ASSERT_EQ(protocol::message_type_to_string(protocol::MessageType::DATA), "DATA");
    ASSERT_EQ(protocol::message_type_to_string(protocol::MessageType::ACK), "ACK");
    ASSERT_EQ(protocol::message_type_to_string(protocol::MessageType::ERROR), "ERROR");
    ASSERT_EQ(protocol::message_type_to_string(protocol::MessageType::UNKNOWN), "UNKNOWN");
}

TEST(protocol_quick_validate) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.max_payload_size = 1000;
    config.little_endian = true;

    // Valid message
    std::vector<uint8_t> valid = {
        0xAA, 0x02, 0x04, 0x00,  // magic, type, length=4
        0x00, 0x00, 0x00, 0x00,  // sequence
        0x00, 0x00,              // checksum
        0x01, 0x02, 0x03, 0x04   // payload
    };
    ASSERT_TRUE(protocol::quick_validate(valid.data(), valid.size(), config));

    // Invalid magic
    std::vector<uint8_t> invalid_magic = valid;
    invalid_magic[0] = 0xBB;
    ASSERT_FALSE(protocol::quick_validate(invalid_magic.data(), invalid_magic.size(), config));

    // Too short
    std::vector<uint8_t> too_short = {0xAA, 0x02};
    ASSERT_FALSE(protocol::quick_validate(too_short.data(), too_short.size(), config));
}

TEST(protocol_big_endian) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = false;
    config.requires_checksum = false;

    std::vector<uint8_t> payload = {0x01, 0x02};
    auto message = protocol::generate_valid_message(
        protocol::MessageType::DATA,
        payload,
        0x12345678,
        config
    );

    // In big endian, length bytes should be [0x00, 0x02]
    ASSERT_EQ(message[2], 0x00);
    ASSERT_EQ(message[3], 0x02);
}

TEST(protocol_empty_payload) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = true;
    config.requires_checksum = false;

    std::vector<uint8_t> empty_payload;
    auto message = protocol::generate_valid_message(
        protocol::MessageType::HEARTBEAT,
        empty_payload,
        1,
        config
    );

    ASSERT_EQ(message.size(), 10);  // Header only
    ASSERT_EQ(message[2], 0x00);    // Length low byte
    ASSERT_EQ(message[3], 0x00);    // Length high byte
}

TEST(protocol_all_message_types) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = true;

    std::vector<protocol::MessageType> types = {
        protocol::MessageType::HANDSHAKE,
        protocol::MessageType::DATA,
        protocol::MessageType::ACK,
        protocol::MessageType::ERROR,
        protocol::MessageType::CONTROL,
        protocol::MessageType::HEARTBEAT,
        protocol::MessageType::DISCONNECT
    };

    for (auto type : types) {
        auto msg = protocol::generate_valid_message(type, {0x01}, 1, config);
        ASSERT_EQ(msg[1], static_cast<uint8_t>(type));
    }
}

// ============================================================================
// Fuzzer Tests
// ============================================================================

TEST(fuzzer_creation) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    const auto& stats = fuzzer.get_stats();
    ASSERT_EQ(stats.total_inputs, 0);
    ASSERT_EQ(stats.crashes_found, 0);
}

TEST(fuzzer_mutate_bit_flip) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;
    config.max_mutations_per_input = 1;

    // Override weights to only use bit flip
    for (auto& pair : config.strategy_weights) {
        pair.second = 0.0;
    }
    config.strategy_weights[fuzzer::MutationStrategy::BIT_FLIP] = 100.0;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    std::vector<uint8_t> input = {0x00, 0x00, 0x00, 0x00};
    auto mutated = fuzzer.mutate(input);

    // Should have exactly one bit flipped
    int diff_bits = 0;
    for (size_t i = 0; i < input.size(); ++i) {
        uint8_t diff = input[i] ^ mutated[i];
        while (diff) {
            diff_bits += diff & 1;
            diff >>= 1;
        }
    }
    ASSERT_EQ(diff_bits, 1);
}

TEST(fuzzer_mutate_byte_insert) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;
    config.max_mutations_per_input = 1;

    for (auto& pair : config.strategy_weights) {
        pair.second = 0.0;
    }
    config.strategy_weights[fuzzer::MutationStrategy::BYTE_INSERT] = 100.0;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    std::vector<uint8_t> input = {0x01, 0x02, 0x03};
    auto mutated = fuzzer.mutate(input);

    ASSERT_EQ(mutated.size(), input.size() + 1);
}

TEST(fuzzer_mutate_byte_delete) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;
    config.max_mutations_per_input = 1;

    for (auto& pair : config.strategy_weights) {
        pair.second = 0.0;
    }
    config.strategy_weights[fuzzer::MutationStrategy::BYTE_DELETE] = 100.0;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    std::vector<uint8_t> input = {0x01, 0x02, 0x03, 0x04};
    auto mutated = fuzzer.mutate(input);

    ASSERT_EQ(mutated.size(), input.size() - 1);
}

TEST(fuzzer_mutate_magic_value) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;
    config.max_mutations_per_input = 1;

    for (auto& pair : config.strategy_weights) {
        pair.second = 0.0;
    }
    config.strategy_weights[fuzzer::MutationStrategy::MAGIC_VALUE] = 100.0;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    std::vector<uint8_t> input = {0x50, 0x50, 0x50, 0x50};
    auto mutated = fuzzer.mutate(input);

    // At least one byte should be a magic value
    bool found_magic = false;
    for (size_t i = 0; i < mutated.size(); ++i) {
        if (mutated[i] != input[i]) {
            uint8_t v = mutated[i];
            if (v == 0x00 || v == 0x01 || v == 0x7F || v == 0x80 || v == 0xFF ||
                v == 0x10 || v == 0x20 || v == 0x40) {
                found_magic = true;
                break;
            }
        }
    }
    ASSERT_TRUE(found_magic);
}

TEST(fuzzer_mutate_integer_overflow) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;
    config.max_mutations_per_input = 1;

    for (auto& pair : config.strategy_weights) {
        pair.second = 0.0;
    }
    config.strategy_weights[fuzzer::MutationStrategy::INTEGER_OVERFLOW] = 100.0;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    std::vector<uint8_t> input = {0x00, 0x00, 0x00, 0x00};
    auto mutated = fuzzer.mutate(input);

    // Should contain max integer values
    bool found_max = false;
    for (auto v : mutated) {
        if (v == 0xFF) {
            found_max = true;
            break;
        }
    }
    ASSERT_TRUE(found_max);
}

TEST(fuzzer_mutate_integer_underflow) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;
    config.max_mutations_per_input = 1;

    for (auto& pair : config.strategy_weights) {
        pair.second = 0.0;
    }
    config.strategy_weights[fuzzer::MutationStrategy::INTEGER_UNDERFLOW] = 100.0;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    std::vector<uint8_t> input = {0xFF, 0xFF, 0xFF, 0xFF};
    auto mutated = fuzzer.mutate(input);

    // Should contain zero values
    bool found_zero = false;
    for (auto v : mutated) {
        if (v == 0x00) {
            found_zero = true;
            break;
        }
    }
    ASSERT_TRUE(found_zero);
}

TEST(fuzzer_mutate_block_shuffle) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;
    config.max_mutations_per_input = 1;

    for (auto& pair : config.strategy_weights) {
        pair.second = 0.0;
    }
    config.strategy_weights[fuzzer::MutationStrategy::BLOCK_SHUFFLE] = 100.0;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    // Need larger input for block shuffle
    std::vector<uint8_t> input(32);
    for (size_t i = 0; i < input.size(); ++i) {
        input[i] = static_cast<uint8_t>(i);
    }
    auto mutated = fuzzer.mutate(input);

    ASSERT_EQ(mutated.size(), input.size());
    // Content should be different (blocks shuffled)
    bool changed = false;
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] != mutated[i]) {
            changed = true;
            break;
        }
    }
    ASSERT_TRUE(changed);
}

TEST(fuzzer_mutate_arithmetic) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;
    config.max_mutations_per_input = 1;

    for (auto& pair : config.strategy_weights) {
        pair.second = 0.0;
    }
    config.strategy_weights[fuzzer::MutationStrategy::ARITHMETIC] = 100.0;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    std::vector<uint8_t> input = {0x10, 0x20, 0x30, 0x40};
    auto mutated = fuzzer.mutate(input);

    // Should have small arithmetic changes
    bool changed = false;
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] != mutated[i]) {
            int8_t diff = static_cast<int8_t>(mutated[i]) - static_cast<int8_t>(input[i]);
            // Arithmetic should change by small amount (typically -10 to +10)
            ASSERT_GE(diff, -20);
            ASSERT_LE(diff, 20);
            changed = true;
        }
    }
    ASSERT_TRUE(changed);
}

TEST(fuzzer_mutate_empty_input) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    std::vector<uint8_t> empty;
    auto mutated = fuzzer.mutate(empty);

    // Empty input may result in empty or minimal output
    // Just verify it doesn't crash
    (void)mutated;
}

TEST(fuzzer_run_basic) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;
    config.max_mutations_per_input = 3;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    // Set up protocol config
    protocol::ProtocolConfig proto_config;
    proto_config.magic_byte = 0xAA;
    fuzzer.set_protocol_config(proto_config);

    // Add seed input
    std::vector<uint8_t> seed = {0xAA, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    fuzzer.add_seed_input(seed);

    // Set up a simple process callback that always succeeds
    int process_count = 0;
    fuzzer.set_process_callback([&process_count](const std::vector<uint8_t>&) {
        process_count++;
        return true;
    });

    // Run fuzzer
    uint64_t crashes = fuzzer.run(100);

    ASSERT_EQ(crashes, 0);
    ASSERT_EQ(process_count, 100);

    const auto& stats = fuzzer.get_stats();
    ASSERT_EQ(stats.total_inputs, 100);
    // Bytes fuzzed should be close to seed size * iterations (mutations may vary size)
    ASSERT_TRUE(stats.bytes_fuzzed > 0);
}

TEST(fuzzer_crash_detection) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    // Add seed input
    std::vector<uint8_t> seed = {0xAA, 0x02, 0x00, 0x00};
    fuzzer.add_seed_input(seed);

    // Process callback that fails on specific input
    int fail_count = 0;
    fuzzer.set_process_callback([&fail_count](const std::vector<uint8_t>& data) {
        // Fail if first byte is 0xFF
        if (!data.empty() && data[0] == 0xFF) {
            fail_count++;
            return false;
        }
        return true;
    });

    // Run enough iterations to likely hit the 0xFF case
    fuzzer.run(1000);

    // We should have detected some crashes
    const auto& stats = fuzzer.get_stats();
    ASSERT_TRUE(stats.crashes_found > 0 || fail_count > 0);
}

TEST(fuzzer_deterministic) {
    // Run fuzzer twice with same seed, should get same results
    std::vector<uint8_t> results1;
    std::vector<uint8_t> results2;

    auto run_fuzzer = [&](std::vector<uint8_t>& results) {
        fuzzer::FuzzerConfig config;
        config.seed = 12345;
        config.deterministic = true;
        config.max_mutations_per_input = 1;

        for (auto& pair : config.strategy_weights) {
            pair.second = 0.0;
        }
        config.strategy_weights[fuzzer::MutationStrategy::BIT_FLIP] = 100.0;

        fuzzer::BinaryProtocolFuzzer fuzzer(config);

        std::vector<uint8_t> seed = {0x00, 0x00, 0x00, 0x00};
        fuzzer.add_seed_input(seed);

        fuzzer.set_process_callback([&results](const std::vector<uint8_t>& data) {
            results.push_back(data[0]);
            return true;
        });

        fuzzer.run(10);
    };

    run_fuzzer(results1);
    run_fuzzer(results2);

    ASSERT_EQ(results1.size(), results2.size());
    for (size_t i = 0; i < results1.size(); ++i) {
        ASSERT_EQ(results1[i], results2[i]);
    }
}

TEST(fuzzer_stop) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    std::vector<uint8_t> seed = {0xAA, 0x02};
    fuzzer.add_seed_input(seed);

    bool callback_called = false;
    fuzzer.set_process_callback([&callback_called, &fuzzer](const std::vector<uint8_t>&) {
        callback_called = true;
        fuzzer.stop();
        return true;
    });

    fuzzer.run(1000);

    ASSERT_TRUE(callback_called);
    ASSERT_TRUE(fuzzer.should_stop());
}

TEST(fuzzer_multiple_seeds) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    // Add multiple seeds
    std::vector<uint8_t> seed1 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> seed2 = {0x04, 0x05, 0x06};
    std::vector<uint8_t> seed3 = {0x07, 0x08, 0x09};
    
    fuzzer.add_seed_input(seed1);
    fuzzer.add_seed_input(seed2);
    fuzzer.add_seed_input(seed3);

    // Set up protocol and run to verify seeds are used
    protocol::ProtocolConfig proto_config;
    proto_config.magic_byte = 0xAA;
    fuzzer.set_protocol_config(proto_config);
    
    int process_count = 0;
    fuzzer.set_process_callback([&process_count](const std::vector<uint8_t>&) {
        process_count++;
        return true;
    });

    // Run a few iterations to verify seeds are being used
    fuzzer.run(10);

    const auto& stats = fuzzer.get_stats();
    ASSERT_GE(stats.total_inputs, 10);
}

TEST(fuzzer_coverage_tracking) {
    fuzzer::FuzzerConfig config;
    config.seed = 42;
    config.deterministic = true;

    fuzzer::BinaryProtocolFuzzer fuzzer(config);

    protocol::ProtocolConfig proto_config;
    proto_config.magic_byte = 0xAA;
    fuzzer.set_protocol_config(proto_config);

    std::vector<uint8_t> seed = {0xAA, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    fuzzer.add_seed_input(seed);

    int count = 0;
    fuzzer.set_process_callback([&count](const std::vector<uint8_t>&) {
        count++;
        return true;
    });

    fuzzer.run(50);

    const auto& stats = fuzzer.get_stats();
    ASSERT_GE(stats.covered_lengths.size(), 1);
}

// ============================================================================
// Utility Function Tests
// ============================================================================

TEST(util_random_bytes) {
    std::mt19937 rng(42);

    auto bytes1 = fuzzer::random_bytes(16, rng);
    auto bytes2 = fuzzer::random_bytes(16, rng);

    ASSERT_EQ(bytes1.size(), 16);
    ASSERT_EQ(bytes2.size(), 16);
    ASSERT_NE(bytes1, bytes2);  // Should be different
}

TEST(util_data_hash) {
    std::vector<uint8_t> data1 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> data2 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> data3 = {0x01, 0x02, 0x04};

    auto hash1 = fuzzer::data_hash(data1);
    auto hash2 = fuzzer::data_hash(data2);
    auto hash3 = fuzzer::data_hash(data3);

    ASSERT_EQ(hash1, hash2);  // Same data = same hash
    ASSERT_NE(hash1, hash3);  // Different data = different hash
}

TEST(util_interesting_values) {
    auto values = fuzzer::get_interesting_values();

    ASSERT_FALSE(values.empty());
    // Should contain common edge case values
    bool found_zero = false;
    bool found_ff = false;
    for (auto v : values) {
        if (v == 0x00) found_zero = true;
        if (v == 0xFF) found_ff = true;
    }
    ASSERT_TRUE(found_zero);
    ASSERT_TRUE(found_ff);
}

TEST(util_random_range) {
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> dist(0, 10);

    // Test random range using standard distribution
    for (int i = 0; i < 100; ++i) {
        int val = dist(rng);
        ASSERT_GE(val, 0);
        ASSERT_LE(val, 10);
    }
}

TEST(util_pick_weighted) {
    // Test weighted selection using map from config
    fuzzer::FuzzerConfig config;
    
    // Find the strategy with highest weight
    fuzzer::MutationStrategy max_strategy = fuzzer::MutationStrategy::BIT_FLIP;
    double max_weight = 0;
    for (const auto& pair : config.strategy_weights) {
        if (pair.second > max_weight) {
            max_weight = pair.second;
            max_strategy = pair.first;
        }
    }
    
    // BIT_FLIP should have highest weight (30.0)
    ASSERT_EQ(max_strategy, fuzzer::MutationStrategy::BIT_FLIP);
    ASSERT_EQ(max_weight, 30.0);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

TEST(edge_case_max_payload) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.max_payload_size = 10000;
    config.little_endian = true;

    // Create message at max payload size
    std::vector<uint8_t> payload(10000, 0x42);
    auto message = protocol::generate_valid_message(
        protocol::MessageType::DATA,
        payload,
        1,
        config
    );

    ASSERT_EQ(message.size(), 10 + 10000);
    ASSERT_TRUE(protocol::quick_validate(message.data(), message.size(), config));
}

TEST(edge_case_zero_sequence) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = true;

    auto message = protocol::generate_valid_message(
        protocol::MessageType::DATA,
        {0x01},
        0,  // Zero sequence number
        config
    );

    ASSERT_TRUE(protocol::quick_validate(message.data(), message.size(), config));
}

TEST(edge_case_null_buffer) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;

    // Parse with null buffer should not crash
    auto parsed = protocol::parse_message(nullptr, 0, config);
    ASSERT_FALSE(parsed.has_value());
}

// ============================================================================
// Malformed Packet Validation Tests
// ============================================================================

TEST(malformed_reserved_type_zero) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = true;

    // Message type 0x00 is reserved
    std::vector<uint8_t> msg = {
        0xAA,                    // magic
        0x00,                    // type = RESERVED (invalid)
        0x04, 0x00,              // length = 4
        0x00, 0x00, 0x00, 0x00,  // sequence
        0x00, 0x00               // checksum
    };

    auto result = protocol::parse_message_detailed(msg.data(), msg.size(), config);
    ASSERT_EQ(result.result, protocol::ValidationResult::ERROR_RESERVED_TYPE);
}

TEST(malformed_length_mismatch) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = true;
    config.requires_checksum = false;

    // Length field says 2 bytes, but we have 4 bytes of payload
    std::vector<uint8_t> msg = {
        0xAA,                    // magic
        0x02,                    // type = DATA
        0x02, 0x00,              // length = 2 (but actual is 4)
        0x00, 0x00, 0x00, 0x00,  // sequence
        0x00, 0x00,              // checksum
        0x01, 0x02, 0x03, 0x04   // 4 bytes payload (exceeds declared length)
    };

    auto result = protocol::parse_message_detailed(msg.data(), msg.size(), config);
    ASSERT_EQ(result.result, protocol::ValidationResult::ERROR_LENGTH_MISMATCH);
}

TEST(malformed_invalid_checksum_field) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = true;
    config.requires_checksum = true;

    // Message with 0x0000 checksum - CRC of header won't be 0x0000 for this data
    // Using payload that produces a non-zero CRC
    std::vector<uint8_t> msg = {
        0xAA,                    // magic
        0x02,                    // type = DATA
        0x04, 0x00,              // length = 4
        0x00, 0x00, 0x00, 0x00,  // sequence
        0x00, 0x00,              // checksum = 0x0000 (suspicious, won't match)
        0xDE, 0xAD, 0xBE, 0xEF   // payload that produces non-zero CRC
    };

    auto result = protocol::parse_message_detailed(msg.data(), msg.size(), config);
    ASSERT_EQ(result.result, protocol::ValidationResult::ERROR_INVALID_CHECKSUM_FIELD);
}

TEST(malformed_invalid_checksum_field_ffff) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = true;
    config.requires_checksum = true;

    // Message with 0xFFFF checksum - CRC of header won't be 0xFFFF for this data
    std::vector<uint8_t> msg = {
        0xAA,                    // magic
        0x02,                    // type = DATA
        0x04, 0x00,              // length = 4
        0x00, 0x00, 0x00, 0x00,  // sequence
        0xFF, 0xFF,              // checksum = 0xFFFF (suspicious, won't match)
        0xDE, 0xAD, 0xBE, 0xEF   // payload that produces non-FFFF CRC
    };

    auto result = protocol::parse_message_detailed(msg.data(), msg.size(), config);
    ASSERT_EQ(result.result, protocol::ValidationResult::ERROR_INVALID_CHECKSUM_FIELD);
}

TEST(malformed_unknown_type_high) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = true;

    // Message type 0xFF is unknown
    std::vector<uint8_t> msg = {
        0xAA,                    // magic
        0xFF,                    // type = UNKNOWN (invalid)
        0x04, 0x00,              // length = 4
        0x00, 0x00, 0x00, 0x00,  // sequence
        0x00, 0x00               // checksum
    };

    auto result = protocol::parse_message_detailed(msg.data(), msg.size(), config);
    ASSERT_EQ(result.result, protocol::ValidationResult::ERROR_UNKNOWN_MESSAGE_TYPE);
}

TEST(malformed_validation_result_strings) {
    // Test new validation result string conversions
    ASSERT_EQ(protocol::validation_result_to_string(
        protocol::ValidationResult::ERROR_LENGTH_MISMATCH), "Length field mismatch");
    ASSERT_EQ(protocol::validation_result_to_string(
        protocol::ValidationResult::ERROR_RESERVED_TYPE), "Reserved message type");
    ASSERT_EQ(protocol::validation_result_to_string(
        protocol::ValidationResult::ERROR_INVALID_CHECKSUM_FIELD), "Invalid checksum field");
}

TEST(malformed_exact_length_match) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = true;
    config.requires_checksum = false;

    // Valid message where actual payload exactly matches declared length
    std::vector<uint8_t> msg = {
        0xAA,                    // magic
        0x02,                    // type = DATA
        0x02, 0x00,              // length = 2
        0x00, 0x00, 0x00, 0x00,  // sequence
        0x00, 0x00,              // checksum
        0x01, 0x02               // exactly 2 bytes payload
    };

    auto result = protocol::parse_message_detailed(msg.data(), msg.size(), config);
    ASSERT_EQ(result.result, protocol::ValidationResult::OK);
    ASSERT_TRUE(result.message.valid);
}

TEST(malformed_trailing_garbage) {
    protocol::ProtocolConfig config;
    config.magic_byte = 0xAA;
    config.little_endian = true;
    config.requires_checksum = false;

    // Message with extra trailing bytes (garbage after payload)
    std::vector<uint8_t> msg = {
        0xAA,                    // magic
        0x02,                    // type = DATA
        0x02, 0x00,              // length = 2
        0x00, 0x00, 0x00, 0x00,  // sequence
        0x00, 0x00,              // checksum
        0x01, 0x02,              // 2 bytes payload
        0xDE, 0xAD, 0xBE, 0xEF   // trailing garbage
    };

    auto result = protocol::parse_message_detailed(msg.data(), msg.size(), config);
    ASSERT_EQ(result.result, protocol::ValidationResult::ERROR_LENGTH_MISMATCH);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== Binary Protocol Fuzzer Tests ===\n\n";

    // CRC16 tests
    std::cout << "--- CRC16 Tests ---\n";
    RUN_TEST(crc16_basic);
    RUN_TEST(crc16_single_byte);
    RUN_TEST(crc16_known_value);
    RUN_TEST(crc16_consistency);
    RUN_TEST(crc16_different_data);
    RUN_TEST(crc16_incremental);

    // Protocol tests
    std::cout << "\n--- Protocol Tests ---\n";
    RUN_TEST(protocol_generate_valid_message);
    RUN_TEST(protocol_parse_valid_message);
    RUN_TEST(protocol_parse_invalid_magic);
    RUN_TEST(protocol_parse_truncated);
    RUN_TEST(protocol_parse_length_overflow);
    RUN_TEST(protocol_message_type_string);
    RUN_TEST(protocol_quick_validate);
    RUN_TEST(protocol_big_endian);
    RUN_TEST(protocol_empty_payload);
    RUN_TEST(protocol_all_message_types);

    // Fuzzer tests
    std::cout << "\n--- Fuzzer Tests ---\n";
    RUN_TEST(fuzzer_creation);
    RUN_TEST(fuzzer_mutate_bit_flip);
    RUN_TEST(fuzzer_mutate_byte_insert);
    RUN_TEST(fuzzer_mutate_byte_delete);
    RUN_TEST(fuzzer_mutate_magic_value);
    RUN_TEST(fuzzer_mutate_integer_overflow);
    RUN_TEST(fuzzer_mutate_integer_underflow);
    RUN_TEST(fuzzer_mutate_block_shuffle);
    RUN_TEST(fuzzer_mutate_arithmetic);
    RUN_TEST(fuzzer_mutate_empty_input);
    RUN_TEST(fuzzer_run_basic);
    RUN_TEST(fuzzer_crash_detection);
    RUN_TEST(fuzzer_deterministic);
    RUN_TEST(fuzzer_stop);
    RUN_TEST(fuzzer_multiple_seeds);
    RUN_TEST(fuzzer_coverage_tracking);

    // Utility tests
    std::cout << "\n--- Utility Tests ---\n";
    RUN_TEST(util_random_bytes);
    RUN_TEST(util_data_hash);
    RUN_TEST(util_interesting_values);
    RUN_TEST(util_random_range);
    RUN_TEST(util_pick_weighted);

    // Edge case tests
    std::cout << "\n--- Edge Case Tests ---\n";
    RUN_TEST(edge_case_max_payload);
    RUN_TEST(edge_case_zero_sequence);
    RUN_TEST(edge_case_null_buffer);

    // Malformed packet validation tests
    std::cout << "\n--- Malformed Packet Validation Tests ---\n";
    RUN_TEST(malformed_reserved_type_zero);
    RUN_TEST(malformed_length_mismatch);
    RUN_TEST(malformed_invalid_checksum_field);
    RUN_TEST(malformed_invalid_checksum_field_ffff);
    RUN_TEST(malformed_unknown_type_high);
    RUN_TEST(malformed_validation_result_strings);
    RUN_TEST(malformed_exact_length_match);
    RUN_TEST(malformed_trailing_garbage);

    // Summary
    std::cout << "\n=== Test Summary ===\n";
    std::cout << "Passed: " << passed << "\n";
    std::cout << "Failed: " << failed << "\n";
    std::cout << "Total:  " << (passed + failed) << "\n";

    return failed > 0 ? 1 : 0;
}
