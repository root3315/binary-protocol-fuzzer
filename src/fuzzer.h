#ifndef FUZZER_H
#define FUZZER_H

#include "protocol.h"
#include <vector>
#include <string>
#include <random>
#include <functional>
#include <map>
#include <set>
#include <chrono>

namespace fuzzer {

// Mutation strategies for transforming input data
// Each strategy targets different classes of vulnerabilities
enum class MutationStrategy {
    BIT_FLIP,           // Flip individual bits - catches flag/boolean handling bugs
    BYTE_FLIP,          // Replace byte with random value - general corruption
    BYTE_INSERT,        // Insert random byte - catches off-by-one and buffer issues
    BYTE_DELETE,        // Remove byte - tests bounds checking
    BYTE_DUPLICATE,     // Duplicate existing byte - catches parsing state issues
    INTEGER_OVERFLOW,   // Replace with max/min integer values
    INTEGER_UNDERFLOW,  // Replace with zero or negative equivalents
    MAGIC_VALUE,        // Insert known dangerous values (0x00, 0xFF, etc.)
    BLOCK_SHUFFLE,      // Swap blocks of data - catches ordering dependencies
    ARITHMETIC,         // Add/subtract small values - catches boundary conditions
    INTERESTING_VALUE   // Insert protocol-specific interesting values
};

// Result from processing a single fuzzed input
struct FuzzResult {
    bool crash_detected;
    bool hang_detected;
    bool assertion_failure;
    std::string error_message;
    std::vector<uint8_t> input;
    size_t input_size;
    uint64_t execution_time_us;
    int signal_number;
    
    FuzzResult() 
        : crash_detected(false)
        , hang_detected(false)
        , assertion_failure(false)
        , input_size(0)
        , execution_time_us(0)
        , signal_number(0) {}
};

// Statistics collected during fuzzing campaign
struct FuzzStats {
    uint64_t total_inputs;
    uint64_t crashes_found;
    uint64_t hangs_found;
    uint64_t unique_crashes;
    uint64_t inputs_per_second;
    uint64_t bytes_fuzzed;
    double avg_execution_time_ms;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_crash_time;
    
    // Coverage information (simplified for this implementation)
    std::set<size_t> covered_lengths;
    std::set<uint8_t> covered_magic_bytes;
    std::set<uint8_t> covered_message_types;
    
    FuzzStats() 
        : total_inputs(0)
        , crashes_found(0)
        , hangs_found(0)
        , unique_crashes(0)
        , inputs_per_second(0)
        , bytes_fuzzed(0)
        , avg_execution_time_ms(0.0) {
        start_time = std::chrono::steady_clock::now();
    }
};

// Configuration for the fuzzer engine
struct FuzzerConfig {
    size_t max_input_size;
    size_t min_input_size;
    size_t max_mutations_per_input;
    uint64_t timeout_us;
    unsigned int seed;
    bool deterministic;
    
    // Mutation strategy weights (higher = more likely)
    std::map<MutationStrategy, double> strategy_weights;
    
    FuzzerConfig()
        : max_input_size(4096)
        , min_input_size(1)
        , max_mutations_per_input(5)
        , timeout_us(100000)  // 100ms default timeout
        , seed(0)  // 0 means use random seed
        , deterministic(false) {
        
        // Default weights favor simpler mutations that find more bugs
        strategy_weights[MutationStrategy::BIT_FLIP] = 30.0;
        strategy_weights[MutationStrategy::BYTE_FLIP] = 25.0;
        strategy_weights[MutationStrategy::BYTE_INSERT] = 10.0;
        strategy_weights[MutationStrategy::BYTE_DELETE] = 10.0;
        strategy_weights[MutationStrategy::BYTE_DUPLICATE] = 8.0;
        strategy_weights[MutationStrategy::INTEGER_OVERFLOW] = 5.0;
        strategy_weights[MutationStrategy::INTEGER_UNDERFLOW] = 5.0;
        strategy_weights[MutationStrategy::MAGIC_VALUE] = 15.0;
        strategy_weights[MutationStrategy::BLOCK_SHUFFLE] = 3.0;
        strategy_weights[MutationStrategy::ARITHMETIC] = 12.0;
        strategy_weights[MutationStrategy::INTERESTING_VALUE] = 10.0;
    }
};

// Callback type for processing fuzzed inputs
// Returns true if input was processed successfully
using ProcessInputCallback = std::function<bool(const std::vector<uint8_t>&)>;

// Callback type for reporting crashes
using CrashCallback = std::function<void(const FuzzResult&)>;

// Main fuzzer engine class
// Implements coverage-guided fuzzing with multiple mutation strategies
class BinaryProtocolFuzzer {
public:
    explicit BinaryProtocolFuzzer(const FuzzerConfig& config = FuzzerConfig());
    ~BinaryProtocolFuzzer();
    
    // Set the callback for processing fuzzed inputs
    void set_process_callback(ProcessInputCallback callback);
    
    // Set the callback for crash reporting
    void set_crash_callback(CrashCallback callback);
    
    // Set protocol configuration for target format
    void set_protocol_config(const protocol::ProtocolConfig& config);
    
    // Add seed inputs to the fuzzing corpus
    void add_seed_input(const std::vector<uint8_t>& input);
    
    // Load seed inputs from file
    bool load_seed_file(const std::string& path);
    
    // Run the fuzzer for specified number of iterations
    // Returns number of crashes found
    uint64_t run(uint64_t iterations);
    
    // Run the fuzzer for specified duration in seconds
    uint64_t run_duration(double seconds);
    
    // Get current statistics
    const FuzzStats& get_stats() const;
    
    // Get configuration
    const FuzzerConfig& get_config() const;
    
    // Save interesting inputs to disk
    bool save_corpus(const std::string& directory) const;
    
    // Load corpus from disk
    bool load_corpus(const std::string& directory);
    
    // Generate a mutated copy of input
    std::vector<uint8_t> mutate(const std::vector<uint8_t>& input);
    
    // Stop fuzzing (for use in callbacks)
    void stop();
    
    // Check if fuzzer should stop
    bool should_stop() const;

private:
    // Internal mutation implementations
    std::vector<uint8_t> mutate_bit_flip(const std::vector<uint8_t>& input);
    std::vector<uint8_t> mutate_byte_flip(const std::vector<uint8_t>& input);
    std::vector<uint8_t> mutate_byte_insert(const std::vector<uint8_t>& input);
    std::vector<uint8_t> mutate_byte_delete(const std::vector<uint8_t>& input);
    std::vector<uint8_t> mutate_byte_duplicate(const std::vector<uint8_t>& input);
    std::vector<uint8_t> mutate_integer_overflow(const std::vector<uint8_t>& input);
    std::vector<uint8_t> mutate_integer_underflow(const std::vector<uint8_t>& input);
    std::vector<uint8_t> mutate_magic_value(const std::vector<uint8_t>& input);
    std::vector<uint8_t> mutate_block_shuffle(const std::vector<uint8_t>& input);
    std::vector<uint8_t> mutate_arithmetic(const std::vector<uint8_t>& input);
    std::vector<uint8_t> mutate_interesting_value(const std::vector<uint8_t>& input);
    
    // Select mutation strategy based on weights
    MutationStrategy select_strategy();
    
    // Update statistics after processing input
    void update_stats(const FuzzResult& result);
    
    // Check if crash is unique (not seen before)
    bool is_unique_crash(const std::vector<uint8_t>& input);
    
    // Generate crash signature for deduplication
    std::string crash_signature(const std::vector<uint8_t>& input);
    
    // Update coverage information from input
    void update_coverage(const std::vector<uint8_t>& input);
    
    FuzzerConfig config_;
    protocol::ProtocolConfig protocol_config_;
    FuzzStats stats_;
    
    ProcessInputCallback process_callback_;
    CrashCallback crash_callback_;
    
    std::mt19937 rng_;
    std::vector<std::vector<uint8_t>> corpus_;
    std::set<std::string> crash_signatures_;
    
    bool stop_requested_;
};

// Utility functions for fuzzing

// Generate random bytes
std::vector<uint8_t> random_bytes(size_t length, std::mt19937& rng);

// Generate interesting values commonly found in security bugs
std::vector<uint8_t> get_interesting_values();

// Calculate hash of data for deduplication
std::string data_hash(const std::vector<uint8_t>& data);

// Write data to file (for saving crashes)
bool write_crash_file(const std::string& path, const std::vector<uint8_t>& data);

} // namespace fuzzer

#endif // FUZZER_H
