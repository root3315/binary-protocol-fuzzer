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
#include <thread>
#include <atomic>

namespace fuzzer {

enum class MutationStrategy {
    BIT_FLIP,
    BYTE_FLIP,
    BYTE_INSERT,
    BYTE_DELETE,
    BYTE_DUPLICATE,
    INTEGER_OVERFLOW,
    INTEGER_UNDERFLOW,
    MAGIC_VALUE,
    BLOCK_SHUFFLE,
    ARITHMETIC,
    INTERESTING_VALUE
};

struct FuzzResult {
    bool crash_detected;
    bool hang_detected;
    bool timeout_enforced;
    bool assertion_failure;
    std::string error_message;
    std::vector<uint8_t> input;
    size_t input_size;
    uint64_t execution_time_us;
    int signal_number;

    FuzzResult()
        : crash_detected(false)
        , hang_detected(false)
        , timeout_enforced(false)
        , assertion_failure(false)
        , input_size(0)
        , execution_time_us(0)
        , signal_number(0) {}
};

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

struct FuzzerConfig {
    size_t max_input_size;
    size_t min_input_size;
    size_t max_mutations_per_input;
    uint64_t timeout_us;
    unsigned int seed;
    bool deterministic;

    std::map<MutationStrategy, double> strategy_weights;

    FuzzerConfig()
        : max_input_size(4096)
        , min_input_size(1)
        , max_mutations_per_input(5)
        , timeout_us(100000)
        , seed(0)
        , deterministic(false) {

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

using ProcessInputCallback = std::function<bool(const std::vector<uint8_t>&)>;
using CrashCallback = std::function<void(const FuzzResult&)>;

class BinaryProtocolFuzzer {
public:
    explicit BinaryProtocolFuzzer(const FuzzerConfig& config = FuzzerConfig());
    ~BinaryProtocolFuzzer();

    void set_process_callback(ProcessInputCallback callback);
    void set_crash_callback(CrashCallback callback);
    void set_protocol_config(const protocol::ProtocolConfig& config);
    void add_seed_input(const std::vector<uint8_t>& input);
    bool load_seed_file(const std::string& path);

    uint64_t run(uint64_t iterations);
    uint64_t run_duration(double seconds);

    const FuzzStats& get_stats() const;
    const FuzzerConfig& get_config() const;

    bool save_corpus(const std::string& directory) const;
    bool load_corpus(const std::string& directory);

    std::vector<uint8_t> mutate(const std::vector<uint8_t>& input);

    void stop();
    bool should_stop() const;

private:
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

    MutationStrategy select_strategy();
    void update_stats(const FuzzResult& result);
    bool is_unique_crash(const std::vector<uint8_t>& input);
    std::string crash_signature(const std::vector<uint8_t>& input);
    void update_coverage(const std::vector<uint8_t>& input);

    bool execute_with_timeout(const std::vector<uint8_t>& input, FuzzResult& result);

    FuzzerConfig config_;
    protocol::ProtocolConfig protocol_config_;
    FuzzStats stats_;

    ProcessInputCallback process_callback_;
    CrashCallback crash_callback_;

    std::mt19937 rng_;
    std::vector<std::vector<uint8_t>> corpus_;
    std::set<std::string> crash_signatures_;

    std::atomic<bool> stop_requested_;
};

std::vector<uint8_t> random_bytes(size_t length, std::mt19937& rng);
std::vector<uint8_t> get_interesting_values();
std::string data_hash(const std::vector<uint8_t>& data);
bool write_crash_file(const std::string& path, const std::vector<uint8_t>& data);

} // namespace fuzzer

#endif // FUZZER_H
