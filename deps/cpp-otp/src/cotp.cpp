/* TOTP / HOTP library
 *
 * See README.md
 * See LICENSE
 *
 * 2021 Z. Patocs
 *
 */

#include "cotp/cotp.hpp"
#include "cotp/otp_factory.hpp"
#include "cotp/otp_uri.hpp"
#include "hmac.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <random>
#include <fstream>

static void init_lib() __attribute__((constructor));

static void init_lib() {
    unsigned int seed;
    size_t size = sizeof(seed);

    // Use C++ random device instead of /dev/urandom
    std::random_device rd;
    seed = rd();

    srand(seed);

    // Register default algorithms
    cotp::OTP::register_hmac_algo("SHA1", [](const std::vector<char>& key, const std::vector<char>& message) {
        std::vector<uint8_t> key_bytes(key.begin(), key.end());
        std::vector<uint8_t> message_bytes(message.begin(), message.end());
        auto hash = HMAC::sha1(key_bytes, message_bytes);
        return std::vector<char>(hash.begin(), hash.end());
    }, 160);
}

namespace cotp {

const std::string OTP::base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

std::map<std::string, Algo_info> OTP::otp_algorithm_map;

OTP::OTP(std::string const& base32_secret, std::string const& algo, size_t digits)
    : m_digits(digits)
    , m_bits(0)
    , m_method(OTP_type::OTP)
    , m_algo(nullptr)
    , m_digest_algo_name(algo)
    , m_base32_secret(base32_secret) {
    if (digits < OTP_MIN_DIGITS || digits > OTP_MAX_DIGITS) {
        throw std::invalid_argument("Invalid number of digits");
    }
}

OTP::OTP(std::string const& base32_secret, size_t bits, OTP_algorithm_ptr algo, std::string const& digest_algo_name, size_t digits)
    : m_digits(digits)
    , m_bits(bits)
    , m_method(OTP_type::OTP)
    , m_algo(algo)
    , m_digest_algo_name(digest_algo_name)
    , m_base32_secret(base32_secret) {
    if (digits < OTP_MIN_DIGITS || digits > OTP_MAX_DIGITS) {
        throw std::invalid_argument("Invalid number of digits");
    }
}

OTP::OTP(OTP&& other)
    : m_digits(other.m_digits)
    , m_bits(other.m_bits)
    , m_method(other.m_method)
    , m_algo(other.m_algo)
    , m_digest_algo_name(std::move(other.m_digest_algo_name))
    , m_base32_secret(std::move(other.m_base32_secret))
    , m_issuer(std::move(other.m_issuer))
    , m_account(std::move(other.m_account)) {
}

OTP& OTP::operator=(OTP&& other) {
    if (this != &other) {
        m_digits = other.m_digits;
        m_bits = other.m_bits;
        m_method = other.m_method;
        m_algo = other.m_algo;
        m_digest_algo_name = std::move(other.m_digest_algo_name);
        m_base32_secret = std::move(other.m_base32_secret);
        m_issuer = std::move(other.m_issuer);
        m_account = std::move(other.m_account);
    }
    return *this;
}

void OTP::set_issuer(std::string const& value) {
    m_issuer = value;
}

void OTP::set_account(std::string const& value) {
    m_account = value;
}

std::string const& OTP::get_issuer() const {
    return m_issuer;
}

std::string const& OTP::get_account() const {
    return m_account;
}

std::string OTP::generate(uint64_t input) const {
    std::vector<char> msg = to_bytes(input);
    std::vector<char> secret = byte_secret();
    
    std::vector<char> hash;
    if (m_algo) {
        hash = m_algo(secret, msg);
    } else {
        auto it = otp_algorithm_map.find(m_digest_algo_name);
        if (it == otp_algorithm_map.end()) {
            throw std::runtime_error("Algorithm not found");
        }
        hash = it->second.algo(secret, msg);
    }
    
    int offset = hash[hash.size() - 1] & 0xf;
    int binary = ((hash[offset] & 0x7f) << 24) |
                 ((hash[offset + 1] & 0xff) << 16) |
                 ((hash[offset + 2] & 0xff) << 8) |
                 (hash[offset + 3] & 0xff);
    
    int otp = binary % static_cast<int>(std::pow(10, m_digits));
    std::stringstream ss;
    ss << std::setw(m_digits) << std::setfill('0') << otp;
    return ss.str();
}

std::vector<char> OTP::byte_secret() const {
    std::string secret = m_base32_secret;
    std::transform(secret.begin(), secret.end(), secret.begin(), ::toupper);
    
    std::vector<char> result;
    result.reserve(secret.length() * 5 / 8);
    
    int buffer = 0;
    int bits_left = 0;
    
    for (char c : secret) {
        size_t val = base32_chars.find(c);
        if (val == std::string::npos) {
            throw std::invalid_argument("Invalid base32 character");
        }
        
        buffer = (buffer << 5) | val;
        bits_left += 5;
        
        while (bits_left >= 8) {
            result.push_back((buffer >> (bits_left - 8)) & 0xFF);
            bits_left -= 8;
        }
    }
    
    return result;
}

std::vector<char> OTP::to_bytes(uint64_t value) {
    std::vector<char> result(8);
    for (int i = 7; i >= 0; --i) {
        result[i] = value & 0xFF;
        value >>= 8;
    }
    return result;
}

std::string OTP::random_base32(size_t len) {
    if (len == 0) {
        len = 16;
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, base32_chars.length() - 1);
    
    std::string result;
    result.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        result += base32_chars[dis(gen)];
    }
    return result;
}

std::string OTP::build_uri() const {
    return build_uri("otp", {});
}

std::string OTP::build_uri(std::string const& otp_type, std::map<std::string, std::string> const& additional_args) const {
    std::stringstream ss;
    ss << "otpauth://" << otp_type << "/";
    
    if (!m_issuer.empty()) {
        ss << m_issuer << ":";
    }
    
    ss << m_account << "?secret=" << m_base32_secret;
    
    if (!m_issuer.empty()) {
        ss << "&issuer=" << m_issuer;
    }
    
    ss << "&algorithm=" << m_digest_algo_name;
    ss << "&digits=" << m_digits;
    
    for (const auto& arg : additional_args) {
        ss << "&" << arg.first << "=" << arg.second;
    }
    
    return ss.str();
}

std::ostream& OTP::print(std::ostream& os) const {
    os << "OTP("
       << "secret=" << m_base32_secret << ", "
       << "digits=" << m_digits << ", "
       << "algorithm=" << m_digest_algo_name;
    
    if (!m_issuer.empty()) {
        os << ", issuer=" << m_issuer;
    }
    if (!m_account.empty()) {
        os << ", account=" << m_account;
    }
    
    os << ")";
    return os;
}

bool OTP::register_hmac_algo(std::string const& name, OTP_algorithm_ptr const algo, size_t bits) {
    if (otp_algorithm_map.find(name) != otp_algorithm_map.end()) {
        return false;
    }
    
    otp_algorithm_map[name] = {name, algo, bits};
    return true;
}

// TOTP implementation
TOTP::TOTP(std::string const& base32_secret, std::string const& algo, size_t digits, size_t interval)
    : OTP(base32_secret, algo, digits)
    , m_interval(interval) {
    m_method = OTP_type::TOTP;
}

TOTP::TOTP(std::string const& base32_secret, size_t bits, OTP_algorithm_ptr algo, std::string const& digest_algo_name, size_t digits, size_t interval)
    : OTP(base32_secret, bits, algo, digest_algo_name, digits)
    , m_interval(interval) {
    m_method = OTP_type::TOTP;
}

TOTP::TOTP(TOTP&& other)
    : OTP(std::move(other))
    , m_interval(other.m_interval) {
}

TOTP& TOTP::operator=(TOTP&& other) {
    if (this != &other) {
        OTP::operator=(std::move(other));
        m_interval = other.m_interval;
    }
    return *this;
}

bool TOTP::compare(std::string const& key, size_t increment, uint64_t for_time) const {
    return compare(std::stoull(key), increment, for_time);
}

bool TOTP::compare(uint64_t key, size_t increment, uint64_t for_time) const {
    for (size_t i = 0; i <= increment; ++i) {
        if (key == std::stoull(code_at(for_time, i))) {
            return true;
        }
    }
    return false;
}

std::string TOTP::code_at(uint64_t for_time, size_t counter_offset) const {
    return generate(timecode(for_time) + counter_offset);
}

std::string TOTP::code() const {
    auto now = std::chrono::system_clock::now();
    auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return code_at(now_seconds, 0);
}

bool TOTP::verify(std::string const& key, uint64_t for_time, size_t valid_window) const {
    return verify(std::stoull(key), for_time, valid_window);
}

bool TOTP::verify(uint64_t key, uint64_t for_time, size_t valid_window) const {
    return compare(key, valid_window, for_time);
}

bool TOTP::verify(std::string const& key, size_t valid_window) const {
    return verify(std::stoull(key), valid_window);
}

bool TOTP::verify(uint64_t key, size_t valid_window) const {
    auto now = std::chrono::system_clock::now();
    auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return verify(key, now_seconds, valid_window);
}

unsigned int TOTP::valid_until(uint64_t for_time, size_t valid_window) const {
    return for_time + (valid_window * m_interval);
}

unsigned int TOTP::seconds_to_next_code(uint64_t for_time) const {
    return m_interval - (for_time % m_interval);
}

unsigned int TOTP::seconds_to_next_code() const {
    auto now = std::chrono::system_clock::now();
    auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return seconds_to_next_code(now_seconds);
}

int TOTP::timecode(uint64_t for_time) const {
    return for_time / m_interval;
}

std::string TOTP::build_uri() const {
    std::map<std::string, std::string> args;
    args["period"] = std::to_string(m_interval);
    return OTP::build_uri("totp", args);
}

std::ostream& TOTP::print(std::ostream& os) const {
    os << "TOTP("
       << "secret=" << m_base32_secret << ", "
       << "digits=" << m_digits << ", "
       << "interval=" << m_interval << ", "
       << "algorithm=" << m_digest_algo_name;
    
    if (!m_issuer.empty()) {
        os << ", issuer=" << m_issuer;
    }
    if (!m_account.empty()) {
        os << ", account=" << m_account;
    }
    
    os << ")";
    return os;
}

// HOTP implementation
HOTP::HOTP(std::string const& base32_secret, std::string const& algo, size_t digits)
    : OTP(base32_secret, algo, digits)
    , m_counter(0) {
    m_method = OTP_type::HOTP;
}

HOTP::HOTP(std::string const& base32_secret, size_t bits, OTP_algorithm_ptr algo, std::string const& digest_algo_name, size_t digits)
    : OTP(base32_secret, bits, algo, digest_algo_name, digits)
    , m_counter(0) {
    m_method = OTP_type::HOTP;
}

HOTP::HOTP(HOTP&& other)
    : OTP(std::move(other))
    , m_counter(other.m_counter) {
}

HOTP& HOTP::operator=(HOTP&& other) {
    if (this != &other) {
        OTP::operator=(std::move(other));
        m_counter = other.m_counter;
    }
    return *this;
}

void HOTP::set_counter(size_t value) {
    m_counter = value;
}

size_t HOTP::get_counter() const {
    return m_counter;
}

bool HOTP::compare(std::string const& key) const {
    return compare(std::stoull(key));
}

bool HOTP::compare(uint64_t key) const {
    return key == std::stoull(code());
}

std::string HOTP::code() const {
    return code_at(m_counter);
}

std::string HOTP::code_at(size_t counter) const {
    return generate(counter);
}

bool HOTP::verify(std::string const& key) const {
    return verify(std::stoull(key));
}

bool HOTP::verify(uint64_t key) const {
    return compare(key);
}

std::string HOTP::build_uri() const {
    std::map<std::string, std::string> args;
    args["counter"] = std::to_string(m_counter);
    return OTP::build_uri("hotp", args);
}

std::ostream& HOTP::print(std::ostream& os) const {
    os << "HOTP("
       << "secret=" << m_base32_secret << ", "
       << "digits=" << m_digits << ", "
       << "counter=" << m_counter << ", "
       << "algorithm=" << m_digest_algo_name;
    
    if (!m_issuer.empty()) {
        os << ", issuer=" << m_issuer;
    }
    if (!m_account.empty()) {
        os << ", account=" << m_account;
    }
    
    os << ")";
    return os;
}

}
