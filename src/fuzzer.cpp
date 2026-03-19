#include "fuzzer.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <functional>

namespace fuzzer {

static const uint8_t INTERESTING_8[] = {
    0x00, 0x01, 0x7F, 0x80, 0xFF
};

static const uint16_t INTERESTING_16[] = {
    0x0000, 0x0001, 0x007F, 0x0080, 0x00FF,
    0x0100, 0x7FFF, 0x8000, 0x8001, 0xFFFF
};

static const uint32_t INTERESTING_32[] = {
    0x00000000, 0x00000001, 0x0000007F, 0x00000080, 0x000000FF,
    0x00000100, 0x00007FFF, 0x00008000, 0x00008001, 0x0000FFFF,
    0x00010000, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFF
};

BinaryProtocolFuzzer::BinaryProtocolFuzzer(const FuzzerConfig& config)
    : config_(config)
    , stop_requested_(false) {

    if (config.seed != 0) {
        rng_.seed(config.seed);
    } else {
        if (!config.deterministic) {
            std::random_device rd;
            rng_.seed(rd());
        } else {
            rng_.seed(42);
        }
    }
}

BinaryProtocolFuzzer::~BinaryProtocolFuzzer() {
}

void BinaryProtocolFuzzer::set_process_callback(ProcessInputCallback callback) {
    process_callback_ = callback;
}

void BinaryProtocolFuzzer::set_crash_callback(CrashCallback callback) {
    crash_callback_ = callback;
}

void BinaryProtocolFuzzer::set_protocol_config(const protocol::ProtocolConfig& config) {
    protocol_config_ = config;
}

void BinaryProtocolFuzzer::add_seed_input(const std::vector<uint8_t>& input) {
    if (input.empty() || input.size() > config_.max_input_size) {
        return;
    }
    corpus_.push_back(input);
}

bool BinaryProtocolFuzzer::load_seed_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (size <= 0 || static_cast<size_t>(size) > config_.max_input_size) {
        return false;
    }

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return false;
    }

    add_seed_input(buffer);
    return true;
}

bool BinaryProtocolFuzzer::execute_with_timeout(
    const std::vector<uint8_t>& input,
    FuzzResult& result
) {
    auto exec_start = std::chrono::steady_clock::now();

    std::packaged_task<bool(const std::vector<uint8_t>&)> task(process_callback_);
    std::future<bool> future = task.get_future();

    std::thread worker([&task, &input]() {
        task(input);
    });

    auto timeout = std::chrono::microseconds(config_.timeout_us);
    std::future_status status = future.wait_for(timeout);

    auto exec_end = std::chrono::steady_clock::now();
    result.execution_time_us = std::chrono::duration_cast<std::chrono::microseconds>(
        exec_end - exec_start).count();

    if (status == std::future_status::timeout) {
        result.hang_detected = true;
        result.timeout_enforced = true;
        result.error_message = "Timeout exceeded - execution terminated";
        worker.detach();
        return false;
    }

    worker.join();

    try {
        bool success = future.get();
        if (!success) {
            result.crash_detected = true;
            result.error_message = "Processing failed";
            return false;
        }
    } catch (const std::exception& e) {
        result.crash_detected = true;
        result.error_message = e.what();
        return false;
    } catch (...) {
        result.crash_detected = true;
        result.error_message = "Unknown exception";
        return false;
    }

    return true;
}

uint64_t BinaryProtocolFuzzer::run(uint64_t iterations) {
    if (corpus_.empty()) {
        std::cerr << "Error: No seed inputs in corpus\n";
        return 0;
    }

    if (!process_callback_) {
        std::cerr << "Error: No process callback set\n";
        return 0;
    }

    uint64_t crashes = 0;
    auto total_start = std::chrono::steady_clock::now();

    for (uint64_t i = 0; i < iterations && !stop_requested_; ++i) {
        std::uniform_int_distribution<size_t> corpus_dist(0, corpus_.size() - 1);
        const auto& base_input = corpus_[corpus_dist(rng_)];

        std::vector<uint8_t> mutated = mutate(base_input);

        FuzzResult result;
        result.input = mutated;
        result.input_size = mutated.size();

        execute_with_timeout(mutated, result);

        update_stats(result);
        update_coverage(mutated);

        if (result.crash_detected || result.hang_detected) {
            if (is_unique_crash(mutated)) {
                crash_signatures_.insert(crash_signature(mutated));
                stats_.unique_crashes++;

                if (crash_callback_) {
                    crash_callback_(result);
                }

                crashes++;
                stats_.last_crash_time = std::chrono::steady_clock::now();
            }
        }

        if ((i + 1) % 10000 == 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - total_start).count();
            if (elapsed > 0) {
                stats_.inputs_per_second = (i + 1) / elapsed;
            }
        }
    }

    return crashes;
}

uint64_t BinaryProtocolFuzzer::run_duration(double seconds) {
    auto start = std::chrono::steady_clock::now();
    auto end = start + std::chrono::milliseconds(static_cast<int>(seconds * 1000));

    uint64_t iterations = 0;
    uint64_t crashes = 0;

    while (std::chrono::steady_clock::now() < end && !stop_requested_) {
        crashes += run(1000);
        iterations += 1000;
    }

    return crashes;
}

const FuzzStats& BinaryProtocolFuzzer::get_stats() const {
    return stats_;
}

const FuzzerConfig& BinaryProtocolFuzzer::get_config() const {
    return config_;
}

bool BinaryProtocolFuzzer::save_corpus(const std::string& directory) const {
    (void)directory;
    return true;
}

bool BinaryProtocolFuzzer::load_corpus(const std::string& directory) {
    (void)directory;
    return true;
}

std::vector<uint8_t> BinaryProtocolFuzzer::mutate(const std::vector<uint8_t>& input) {
    if (input.empty()) {
        return input;
    }

    std::vector<uint8_t> result = input;

    std::uniform_int_distribution<size_t> num_mutations(1, config_.max_mutations_per_input);
    size_t mutations = num_mutations(rng_);

    for (size_t i = 0; i < mutations; ++i) {
        MutationStrategy strategy = select_strategy();

        switch (strategy) {
            case MutationStrategy::BIT_FLIP:
                result = mutate_bit_flip(result);
                break;
            case MutationStrategy::BYTE_FLIP:
                result = mutate_byte_flip(result);
                break;
            case MutationStrategy::BYTE_INSERT:
                result = mutate_byte_insert(result);
                break;
            case MutationStrategy::BYTE_DELETE:
                result = mutate_byte_delete(result);
                break;
            case MutationStrategy::BYTE_DUPLICATE:
                result = mutate_byte_duplicate(result);
                break;
            case MutationStrategy::INTEGER_OVERFLOW:
                result = mutate_integer_overflow(result);
                break;
            case MutationStrategy::INTEGER_UNDERFLOW:
                result = mutate_integer_underflow(result);
                break;
            case MutationStrategy::MAGIC_VALUE:
                result = mutate_magic_value(result);
                break;
            case MutationStrategy::BLOCK_SHUFFLE:
                result = mutate_block_shuffle(result);
                break;
            case MutationStrategy::ARITHMETIC:
                result = mutate_arithmetic(result);
                break;
            case MutationStrategy::INTERESTING_VALUE:
                result = mutate_interesting_value(result);
                break;
        }

        if (result.size() > config_.max_input_size) {
            result.resize(config_.max_input_size);
        }
        if (result.size() < config_.min_input_size) {
            result = input;
        }
    }

    return result;
}

void BinaryProtocolFuzzer::stop() {
    stop_requested_ = true;
}

bool BinaryProtocolFuzzer::should_stop() const {
    return stop_requested_;
}

std::vector<uint8_t> BinaryProtocolFuzzer::mutate_bit_flip(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> result = input;
    if (result.empty()) return result;

    std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 1);
    std::uniform_int_distribution<int> bit_dist(0, 7);

    size_t pos = pos_dist(rng_);
    int bit = bit_dist(rng_);

    result[pos] ^= (1 << bit);
    return result;
}

std::vector<uint8_t> BinaryProtocolFuzzer::mutate_byte_flip(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> result = input;
    if (result.empty()) return result;

    std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 1);
    std::uniform_int_distribution<int> byte_dist(0, 255);

    size_t pos = pos_dist(rng_);
    result[pos] = static_cast<uint8_t>(byte_dist(rng_));
    return result;
}

std::vector<uint8_t> BinaryProtocolFuzzer::mutate_byte_insert(const std::vector<uint8_t>& input) {
    if (input.size() >= config_.max_input_size) {
        return input;
    }

    std::vector<uint8_t> result = input;
    std::uniform_int_distribution<size_t> pos_dist(0, result.size());
    std::uniform_int_distribution<int> byte_dist(0, 255);

    size_t pos = pos_dist(rng_);
    uint8_t value = static_cast<uint8_t>(byte_dist(rng_));

    result.insert(result.begin() + pos, value);
    return result;
}

std::vector<uint8_t> BinaryProtocolFuzzer::mutate_byte_delete(const std::vector<uint8_t>& input) {
    if (input.size() <= config_.min_input_size) {
        return input;
    }

    std::vector<uint8_t> result = input;
    std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 1);

    size_t pos = pos_dist(rng_);
    result.erase(result.begin() + pos);
    return result;
}

std::vector<uint8_t> BinaryProtocolFuzzer::mutate_byte_duplicate(const std::vector<uint8_t>& input) {
    if (input.empty() || input.size() >= config_.max_input_size) {
        return input;
    }

    std::vector<uint8_t> result = input;
    std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 1);

    size_t pos = pos_dist(rng_);
    uint8_t value = result[pos];
    result.insert(result.begin() + pos, value);
    return result;
}

std::vector<uint8_t> BinaryProtocolFuzzer::mutate_integer_overflow(const std::vector<uint8_t>& input) {
    if (input.size() < 2) {
        return input;
    }

    std::vector<uint8_t> result = input;
    std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 2);

    size_t pos = pos_dist(rng_);

    result[pos] = 0xFF;
    if (pos + 1 < result.size()) {
        result[pos + 1] = 0xFF;
    }

    return result;
}

std::vector<uint8_t> BinaryProtocolFuzzer::mutate_integer_underflow(const std::vector<uint8_t>& input) {
    if (input.size() < 2) {
        return input;
    }

    std::vector<uint8_t> result = input;
    std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 2);

    size_t pos = pos_dist(rng_);

    result[pos] = 0x00;
    if (pos + 1 < result.size()) {
        result[pos + 1] = 0x00;
    }

    return result;
}

std::vector<uint8_t> BinaryProtocolFuzzer::mutate_magic_value(const std::vector<uint8_t>& input) {
    if (input.empty()) {
        return input;
    }

    std::vector<uint8_t> result = input;
    std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 1);

    static const uint8_t magic_values[] = {
        0x00, 0x01, 0x7F, 0x80, 0xFF,
        0x10, 0x20, 0x40, 0x80
    };

    std::uniform_int_distribution<size_t> val_dist(0, sizeof(magic_values) - 1);

    size_t pos = pos_dist(rng_);
    result[pos] = magic_values[val_dist(rng_)];

    return result;
}

std::vector<uint8_t> BinaryProtocolFuzzer::mutate_block_shuffle(const std::vector<uint8_t>& input) {
    if (input.size() < 4) {
        return input;
    }

    std::vector<uint8_t> result = input;

    std::uniform_int_distribution<size_t> block_size(1, std::min<size_t>(8, result.size() / 2));
    std::uniform_int_distribution<size_t> pos1_dist(0, result.size() / 2);

    size_t size = block_size(rng_);
    size_t pos1 = pos1_dist(rng_);
    size_t pos2 = pos1_dist(rng_) + result.size() / 2;

    if (pos1 + size > result.size() || pos2 + size > result.size()) {
        return input;
    }

    for (size_t i = 0; i < size; ++i) {
        std::swap(result[pos1 + i], result[pos2 + i]);
    }

    return result;
}

std::vector<uint8_t> BinaryProtocolFuzzer::mutate_arithmetic(const std::vector<uint8_t>& input) {
    if (input.empty()) {
        return input;
    }

    std::vector<uint8_t> result = input;
    std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 1);
    std::uniform_int_distribution<int> delta_dist(-5, 5);

    size_t pos = pos_dist(rng_);
    int delta = delta_dist(rng_);

    int new_value = static_cast<int>(result[pos]) + delta;
    result[pos] = static_cast<uint8_t>(new_value & 0xFF);

    return result;
}

std::vector<uint8_t> BinaryProtocolFuzzer::mutate_interesting_value(const std::vector<uint8_t>& input) {
    if (input.size() < 4) {
        return input;
    }

    std::vector<uint8_t> result = input;
    std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 4);
    std::uniform_int_distribution<int> size_select(0, 2);

    size_t pos = pos_dist(rng_);
    int size_type = size_select(rng_);

    switch (size_type) {
        case 0: {
            std::uniform_int_distribution<size_t> val_dist(0, sizeof(INTERESTING_8) - 1);
            result[pos] = INTERESTING_8[val_dist(rng_)];
            break;
        }
        case 1: {
            std::uniform_int_distribution<size_t> val_dist(0, sizeof(INTERESTING_16) - 1);
            uint16_t val = INTERESTING_16[val_dist(rng_)];
            result[pos] = val & 0xFF;
            if (pos + 1 < result.size()) {
                result[pos + 1] = (val >> 8) & 0xFF;
            }
            break;
        }
        case 2: {
            std::uniform_int_distribution<size_t> val_dist(0, sizeof(INTERESTING_32) - 1);
            uint32_t val = INTERESTING_32[val_dist(rng_)];
            for (int i = 0; i < 4 && pos + i < result.size(); ++i) {
                result[pos + i] = (val >> (i * 8)) & 0xFF;
            }
            break;
        }
    }

    return result;
}

MutationStrategy BinaryProtocolFuzzer::select_strategy() {
    double total_weight = 0.0;
    for (const auto& pair : config_.strategy_weights) {
        total_weight += pair.second;
    }

    std::uniform_real_distribution<double> dist(0.0, total_weight);
    double selection = dist(rng_);

    double cumulative = 0.0;
    for (const auto& pair : config_.strategy_weights) {
        cumulative += pair.second;
        if (selection <= cumulative) {
            return pair.first;
        }
    }

    return MutationStrategy::BIT_FLIP;
}

void BinaryProtocolFuzzer::update_stats(const FuzzResult& result) {
    stats_.total_inputs++;
    stats_.bytes_fuzzed += result.input_size;

    if (result.crash_detected) {
        stats_.crashes_found++;
    }
    if (result.hang_detected) {
        stats_.hangs_found++;
    }

    double current_avg = stats_.avg_execution_time_ms;
    double new_value = result.execution_time_us / 1000.0;
    stats_.avg_execution_time_ms = current_avg + (new_value - current_avg) / stats_.total_inputs;
}

bool BinaryProtocolFuzzer::is_unique_crash(const std::vector<uint8_t>& input) {
    return crash_signatures_.find(crash_signature(input)) == crash_signatures_.end();
}

std::string BinaryProtocolFuzzer::crash_signature(const std::vector<uint8_t>& input) {
    return data_hash(input);
}

void BinaryProtocolFuzzer::update_coverage(const std::vector<uint8_t>& input) {
    stats_.covered_lengths.insert(input.size());

    if (!input.empty()) {
        stats_.covered_magic_bytes.insert(input[0]);
    }

    if (input.size() >= 2) {
        stats_.covered_message_types.insert(input[1]);
    }
}

std::vector<uint8_t> random_bytes(size_t length, std::mt19937& rng) {
    std::vector<uint8_t> result(length);
    std::uniform_int_distribution<int> dist(0, 255);

    for (size_t i = 0; i < length; ++i) {
        result[i] = static_cast<uint8_t>(dist(rng));
    }

    return result;
}

std::vector<uint8_t> get_interesting_values() {
    std::vector<uint8_t> result;

    for (uint8_t v : INTERESTING_8) {
        result.push_back(v);
    }

    return result;
}

std::string data_hash(const std::vector<uint8_t>& data) {
    const uint64_t FNV_PRIME = 1099511628211ULL;
    const uint64_t FNV_OFFSET = 14695981039346656037ULL;

    uint64_t hash = FNV_OFFSET;
    for (uint8_t byte : data) {
        hash ^= byte;
        hash *= FNV_PRIME;
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << hash;
    return oss.str();
}

bool write_crash_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

} // namespace fuzzer
