#include "protocol.h"
#include <cstring>
#include <sstream>
#include <algorithm>

namespace protocol {

// Helper function to convert byte to hex string
// Declared early to be available for error message construction
static std::string to_hex(uint8_t byte);

// CRC16-CCITT lookup table for fast checksum computation
// Precomputed to avoid runtime polynomial division
static const uint16_t CRC16_TABLE[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
    0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
    0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
    0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};

uint16_t calculate_crc16(const uint8_t* data, size_t length) {
    // Initialize CRC with 0xFFFF per CCITT standard
    // This catches leading zero bytes that would otherwise not affect the checksum
    uint16_t crc = 0xFFFF;

    for (size_t i = 0; i < length; ++i) {
        // XOR byte into high byte of CRC, then use table lookup
        // This is faster than bit-by-bit polynomial division
        uint8_t index = (crc >> 8) ^ data[i];
        crc = (crc << 8) ^ CRC16_TABLE[index];
    }

    return crc;
}

void header_to_network(MessageHeader& header, bool little_endian) {
    // Convert multi-byte fields to network byte order
    // Big-endian is standard for network protocols
    if (!little_endian) {
        // Convert to big-endian (network byte order)
        uint16_t len = header.length;
        header.length = ((len & 0x00FF) << 8) | ((len & 0xFF00) >> 8);

        uint32_t seq = header.sequence;
        header.sequence = ((seq & 0x000000FF) << 24) |
                          ((seq & 0x0000FF00) << 8) |
                          ((seq & 0x00FF0000) >> 8) |
                          ((seq & 0xFF000000) >> 24);

        uint16_t chk = header.checksum;
        header.checksum = ((chk & 0x00FF) << 8) | ((chk & 0xFF00) >> 8);
    }
    // Little-endian systems can use values directly
}

void header_from_network(MessageHeader& header, bool little_endian) {
    // Convert from network byte order to host byte order
    // Same operation as to_network since byte swap is symmetric
    header_to_network(header, little_endian);
}

std::optional<ParsedMessage> parse_message(
    const uint8_t* data,
    size_t length,
    const ProtocolConfig& config
) {
    // Reject obviously invalid inputs early
    if (!data || length < config.min_header_size) {
        return std::nullopt;
    }

    ParsedMessage msg;

    // Copy header bytes directly into structure
    // Using memcpy to avoid alignment issues with packed struct
    std::memcpy(&msg.header, data, sizeof(MessageHeader));

    // Convert header fields from network byte order
    header_from_network(msg.header, config.little_endian);

    // Validate magic byte - first line of defense against malformed data
    if (msg.header.magic != config.magic_byte) {
        msg.error_message = "Invalid magic byte: expected 0x" +
                           to_hex(config.magic_byte) + ", got 0x" +
                           to_hex(msg.header.magic);
        return msg;
    }

    // Validate message type is within known range
    if (static_cast<uint8_t>(msg.header.type) > 0x07) {
        msg.error_message = "Unknown message type: 0x" +
                           to_hex(static_cast<uint8_t>(msg.header.type));
        msg.valid = false;
        return msg;
    }

    // Check payload length doesn't exceed configured maximum
    // Prevents buffer overflow attempts and memory exhaustion
    if (msg.header.length > config.max_payload_size) {
        msg.error_message = "Payload length " + std::to_string(msg.header.length) +
                           " exceeds maximum " + std::to_string(config.max_payload_size);
        msg.valid = false;
        return msg;
    }

    // Verify we have enough data for the claimed payload
    size_t total_expected = sizeof(MessageHeader) + msg.header.length;
    if (length < total_expected) {
        msg.error_message = "Truncated message: expected " +
                           std::to_string(total_expected) + " bytes, got " +
                           std::to_string(length);
        msg.valid = false;
        return msg;
    }

    // Copy payload if present
    if (msg.header.length > 0) {
        msg.payload.resize(msg.header.length);
        std::memcpy(msg.payload.data(), data + sizeof(MessageHeader), msg.header.length);
    }

    // Verify checksum if required by protocol configuration
    if (config.requires_checksum) {
        uint16_t computed = calculate_crc16(data, sizeof(MessageHeader) - 2);
        if (computed != msg.header.checksum) {
            msg.error_message = "Checksum mismatch: expected 0x" + to_hex(msg.header.checksum) +
                               ", computed 0x" + to_hex(computed);
            msg.valid = false;
            return msg;
        }
    }

    msg.valid = true;
    return msg;
}

ParseResult parse_message_detailed(
    const uint8_t* data,
    size_t length,
    const ProtocolConfig& config
) {
    ParseResult result;

    // Validate input pointer
    if (!data) {
        result.result = ValidationResult::ERROR_NULL_POINTER;
        result.error_detail = "Null data pointer provided";
        return result;
    }

    // Validate minimum data length
    if (length < config.min_header_size) {
        result.result = ValidationResult::ERROR_INSUFFICIENT_DATA;
        result.error_detail = "Data length " + std::to_string(length) +
                             " is less than minimum header size " +
                             std::to_string(config.min_header_size);
        return result;
    }

    // Copy header bytes directly into structure
    std::memcpy(&result.message.header, data, sizeof(MessageHeader));

    // Convert header fields from network byte order
    header_from_network(result.message.header, config.little_endian);

    // Validate magic byte
    if (result.message.header.magic != config.magic_byte) {
        result.result = ValidationResult::ERROR_INVALID_MAGIC;
        result.error_detail = "Invalid magic byte: expected 0x" +
                             to_hex(config.magic_byte) + ", got 0x" +
                             to_hex(result.message.header.magic);
        return result;
    }

    // Validate message type - check for valid range and reserved types
    uint8_t msg_type = static_cast<uint8_t>(result.message.header.type);
    if (msg_type == 0x00) {
        // Type 0x00 is UNKNOWN/reserved - reject explicitly
        result.result = ValidationResult::ERROR_RESERVED_TYPE;
        result.error_detail = "Message type 0x00 is reserved and not allowed";
        return result;
    }
    if (msg_type > 0x07) {
        result.result = ValidationResult::ERROR_UNKNOWN_MESSAGE_TYPE;
        result.error_detail = "Unknown message type: 0x" + to_hex(msg_type);
        return result;
    }

    // Validate payload length field - check for zero-length with non-zero actual data
    if (result.message.header.length > config.max_payload_size) {
        result.result = ValidationResult::ERROR_PAYLOAD_TOO_LARGE;
        result.error_detail = "Payload length " + std::to_string(result.message.header.length) +
                             " exceeds maximum allowed " +
                             std::to_string(config.max_payload_size);
        return result;
    }

    // Validate that length field is consistent with actual data
    // Length field claims more payload than we have
    size_t total_expected = sizeof(MessageHeader) + result.message.header.length;
    if (length < total_expected) {
        result.result = ValidationResult::ERROR_TRUNCATED_MESSAGE;
        result.error_detail = "Truncated message: expected " +
                             std::to_string(total_expected) + " bytes, got " +
                             std::to_string(length);
        return result;
    }

    // Check for length field mismatch - actual data exceeds claimed length
    // This catches malformed packets where length is understated
    size_t actual_payload = length - sizeof(MessageHeader);
    if (actual_payload > result.message.header.length) {
        result.result = ValidationResult::ERROR_LENGTH_MISMATCH;
        result.error_detail = "Actual payload " + std::to_string(actual_payload) +
                             " exceeds declared length " +
                             std::to_string(result.message.header.length);
        return result;
    }

    // Validate checksum field - reject packets with suspicious checksum values
    // All-zero or all-ones checksums often indicate corrupted/uninitialized data
    if (config.requires_checksum) {
        uint16_t computed = calculate_crc16(data, sizeof(MessageHeader) - 2);
        
        // Check for suspicious checksum values that don't match computed CRC
        if ((result.message.header.checksum == 0x0000 || 
            result.message.header.checksum == 0xFFFF) &&
            computed != result.message.header.checksum) {
            result.result = ValidationResult::ERROR_INVALID_CHECKSUM_FIELD;
            result.error_detail = "Suspicious checksum value 0x" +
                                 to_hex(result.message.header.checksum >> 8) +
                                 to_hex(result.message.header.checksum & 0xFF) +
                                 " does not match computed 0x" +
                                 to_hex(computed >> 8) +
                                 to_hex(computed & 0xFF);
            return result;
        }
    }

    // Copy payload if present
    if (result.message.header.length > 0) {
        result.message.payload.resize(result.message.header.length);
        std::memcpy(result.message.payload.data(),
                   data + sizeof(MessageHeader),
                   result.message.header.length);
    }

    // Verify checksum if required
    if (config.requires_checksum) {
        uint16_t computed = calculate_crc16(data, sizeof(MessageHeader) - 2);
        if (computed != result.message.header.checksum) {
            result.result = ValidationResult::ERROR_CHECKSUM_MISMATCH;
            result.error_detail = "Checksum mismatch: expected 0x" +
                                 to_hex(result.message.header.checksum) +
                                 ", computed 0x" + to_hex(computed);
            return result;
        }
    }

    result.result = ValidationResult::OK;
    result.message.valid = true;
    return result;
}

std::vector<uint8_t> serialize_message(
    const ParsedMessage& message,
    const ProtocolConfig& config
) {
    std::vector<uint8_t> result;

    // Calculate total size needed
    size_t total_size = sizeof(MessageHeader) + message.payload.size();
    result.resize(total_size);

    // Copy header
    MessageHeader header = message.header;
    header.length = static_cast<uint16_t>(message.payload.size());

    // Recalculate checksum for serialized data
    if (config.requires_checksum) {
        header.checksum = calculate_crc16(
            reinterpret_cast<const uint8_t*>(&header),
            sizeof(MessageHeader) - 2
        );
    }

    // Convert to network byte order before serialization
    header_to_network(header, config.little_endian);

    // Copy header bytes
    std::memcpy(result.data(), &header, sizeof(MessageHeader));

    // Copy payload if present
    if (!message.payload.empty()) {
        std::memcpy(result.data() + sizeof(MessageHeader),
                   message.payload.data(),
                   message.payload.size());
    }

    return result;
}

bool quick_validate(const uint8_t* data, size_t length, const ProtocolConfig& config) {
    if (!data || length < config.min_header_size) {
        return false;
    }

    // Check magic byte first - fastest rejection test
    if (data[0] != config.magic_byte) {
        return false;
    }

    // Extract length field and verify it's reasonable
    // This catches many malformed inputs without full parsing
    uint16_t payload_len;
    std::memcpy(&payload_len, data + 2, sizeof(uint16_t));

    if (!config.little_endian) {
        payload_len = ((payload_len & 0x00FF) << 8) | ((payload_len & 0xFF00) >> 8);
    }

    if (payload_len > config.max_payload_size) {
        return false;
    }

    // Verify we have enough bytes for header + payload
    return length >= sizeof(MessageHeader) + payload_len;
}

std::string message_type_to_string(MessageType type) {
    switch (type) {
        case MessageType::HANDSHAKE: return "HANDSHAKE";
        case MessageType::DATA: return "DATA";
        case MessageType::ACK: return "ACK";
        case MessageType::ERROR: return "ERROR";
        case MessageType::CONTROL: return "CONTROL";
        case MessageType::HEARTBEAT: return "HEARTBEAT";
        case MessageType::DISCONNECT: return "DISCONNECT";
        default: return "UNKNOWN";
    }
}

std::string validation_result_to_string(ValidationResult result) {
    switch (result) {
        case ValidationResult::OK:
            return "OK";
        case ValidationResult::ERROR_NULL_POINTER:
            return "Null pointer error";
        case ValidationResult::ERROR_INSUFFICIENT_DATA:
            return "Insufficient data";
        case ValidationResult::ERROR_INVALID_MAGIC:
            return "Invalid magic byte";
        case ValidationResult::ERROR_UNKNOWN_MESSAGE_TYPE:
            return "Unknown message type";
        case ValidationResult::ERROR_PAYLOAD_TOO_LARGE:
            return "Payload too large";
        case ValidationResult::ERROR_TRUNCATED_MESSAGE:
            return "Truncated message";
        case ValidationResult::ERROR_CHECKSUM_MISMATCH:
            return "Checksum mismatch";
        case ValidationResult::ERROR_INVALID_LENGTH_FIELD:
            return "Invalid length field";
        case ValidationResult::ERROR_LENGTH_MISMATCH:
            return "Length field mismatch";
        case ValidationResult::ERROR_RESERVED_TYPE:
            return "Reserved message type";
        case ValidationResult::ERROR_INVALID_CHECKSUM_FIELD:
            return "Invalid checksum field";
        default:
            return "Unknown error";
    }
}

std::vector<uint8_t> generate_valid_message(
    MessageType type,
    const std::vector<uint8_t>& payload,
    uint32_t sequence,
    const ProtocolConfig& config
) {
    ParsedMessage msg;
    msg.header.magic = config.magic_byte;
    msg.header.type = type;
    msg.header.length = static_cast<uint16_t>(payload.size());
    msg.header.sequence = sequence;
    msg.header.checksum = 0;  // Will be recalculated
    msg.payload = payload;
    msg.valid = true;

    return serialize_message(msg, config);
}

// to_hex implementation (declared earlier in the file)
static std::string to_hex(uint8_t byte) {
    static const char* hex_chars = "0123456789ABCDEF";
    std::string result;
    result += hex_chars[(byte >> 4) & 0x0F];
    result += hex_chars[byte & 0x0F];
    return result;
}

} // namespace protocol
