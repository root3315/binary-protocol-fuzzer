#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <optional>

namespace protocol {

// Protocol message types for different binary protocol formats
enum class MessageType : uint8_t {
    UNKNOWN = 0x00,
    HANDSHAKE = 0x01,
    DATA = 0x02,
    ACK = 0x03,
    ERROR = 0x04,
    CONTROL = 0x05,
    HEARTBEAT = 0x06,
    DISCONNECT = 0x07
};

// Header structure common to many binary protocols
// Using packed attributes to ensure exact binary layout
#pragma pack(push, 1)
struct MessageHeader {
    uint8_t magic;          // Magic byte to identify protocol
    MessageType type;       // Message type identifier
    uint16_t length;        // Payload length (network byte order)
    uint32_t sequence;      // Sequence number for ordering
    uint16_t checksum;      // CRC16 checksum for integrity
};
#pragma pack(pop)

// Parsed message representation with validation state
struct ParsedMessage {
    MessageHeader header;
    std::vector<uint8_t> payload;
    bool valid;
    std::string error_message;

    ParsedMessage() : valid(false) {
        header = {};
    }
};

// Protocol configuration for different binary formats
struct ProtocolConfig {
    uint8_t magic_byte;
    size_t min_header_size;
    size_t max_payload_size;
    bool requires_checksum;
    bool little_endian;

    ProtocolConfig()
        : magic_byte(0xAA)
        , min_header_size(10)
        , max_payload_size(65535)
        , requires_checksum(true)
        , little_endian(false) {}
};

// Validation result codes for detailed error reporting
enum class ValidationResult {
    OK,
    ERROR_NULL_POINTER,
    ERROR_INSUFFICIENT_DATA,
    ERROR_INVALID_MAGIC,
    ERROR_UNKNOWN_MESSAGE_TYPE,
    ERROR_PAYLOAD_TOO_LARGE,
    ERROR_TRUNCATED_MESSAGE,
    ERROR_CHECKSUM_MISMATCH,
    ERROR_INVALID_LENGTH_FIELD
};

// Extended parsing result with detailed error information
struct ParseResult {
    ParsedMessage message;
    ValidationResult result;
    std::string error_detail;

    ParseResult() : result(ValidationResult::OK) {}
};

// CRC16 calculation for message integrity verification
// Uses CCITT polynomial commonly found in network protocols
uint16_t calculate_crc16(const uint8_t* data, size_t length);

// Convert header fields between host and network byte order
void header_to_network(MessageHeader& header, bool little_endian);
void header_from_network(MessageHeader& header, bool little_endian);

// Parse raw bytes into a structured message
// Returns nullopt if the data is too short or malformed
std::optional<ParsedMessage> parse_message(
    const uint8_t* data,
    size_t length,
    const ProtocolConfig& config
);

// Parse with detailed error reporting
ParseResult parse_message_detailed(
    const uint8_t* data,
    size_t length,
    const ProtocolConfig& config
);

// Serialize a parsed message back to raw bytes
// Used for round-trip testing and mutation verification
std::vector<uint8_t> serialize_message(
    const ParsedMessage& message,
    const ProtocolConfig& config
);

// Validate message structure without full parsing
// Quick check to filter obviously invalid inputs
bool quick_validate(const uint8_t* data, size_t length, const ProtocolConfig& config);

// Get human-readable message type name for reporting
std::string message_type_to_string(MessageType type);

// Get human-readable validation result description
std::string validation_result_to_string(ValidationResult result);

// Generate a valid message with the given parameters
// Used as seed for fuzzing campaigns
std::vector<uint8_t> generate_valid_message(
    MessageType type,
    const std::vector<uint8_t>& payload,
    uint32_t sequence,
    const ProtocolConfig& config
);

} // namespace protocol

#endif // PROTOCOL_H
