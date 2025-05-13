/* TOTP / HOTP library
 *
 * See README.md
 * See LICENSE
 *
 * 2021 Z. Patocs
 *
 */

#pragma once

#include <string>
#include <map>
#include <stdexcept>

namespace cotp {

class OTP_URI {
public:
    OTP_URI() = default;
    ~OTP_URI() = default;

    void set_type(const std::string& type) { m_type = type; }
    void set_account(const std::string& account) { m_account = account; }
    void set_secret(const std::string& secret) { m_secret = secret; }
    void set_issuer(const std::string& issuer) { m_issuer = issuer; }
    void set_algorithm(const std::string& algorithm) { m_algorithm = algorithm; }
    void set_digits(size_t digits) { m_digits = digits; }
    void set_counter(size_t counter) { m_counter = counter; }
    void set_period(size_t period) { m_period = period; }

    const std::string& get_type() const { return m_type; }
    const std::string& get_account() const { return m_account; }
    const std::string& get_secret() const { return m_secret; }
    const std::string& get_issuer() const { return m_issuer; }
    const std::string& get_algorithm() const { return m_algorithm; }
    size_t get_digits() const { return m_digits; }
    size_t get_counter() const { return m_counter; }
    size_t get_period() const { return m_period; }

    std::string get_uri() const {
        std::string uri = "otpauth://" + m_type + "/";
        
        if (!m_issuer.empty()) {
            uri += m_issuer + ":";
        }
        
        uri += m_account + "?secret=" + m_secret;
        
        if (!m_issuer.empty()) {
            uri += "&issuer=" + m_issuer;
        }
        
        uri += "&algorithm=" + m_algorithm;
        uri += "&digits=" + std::to_string(m_digits);
        
        if (m_type == "hotp") {
            uri += "&counter=" + std::to_string(m_counter);
        } else if (m_type == "totp") {
            uri += "&period=" + std::to_string(m_period);
        }
        
        return uri;
    }

private:
    std::string m_type;
    std::string m_account;
    std::string m_secret;
    std::string m_issuer;
    std::string m_algorithm;
    size_t m_digits = 6;
    size_t m_counter = 0;
    size_t m_period = 30;
};

} // namespace cotp