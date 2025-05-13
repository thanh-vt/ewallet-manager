/* TOTP / HOTP library
 *
 * See README.md
 * See LICENSE
 *
 * 2021 Z. Patocs
 *
 */

#pragma once

#include "cotp.hpp"
#include "otp_uri.hpp"
#include <memory>
#include <string>

namespace cotp {

class OTP_factory {
public:
    static OTP_ptr create_from_uri(const std::string& uri) {
        OTP_URI otp_uri;
        parse_uri(uri, otp_uri);
        return create_from_uri(otp_uri);
    }

    static OTP_ptr create_from_uri(const OTP_URI& uri) {
        const std::string& type = uri.get_type();
        if (type == "totp") {
            return std::make_shared<TOTP>(
                uri.get_secret(),
                uri.get_algorithm(),
                uri.get_digits(),
                uri.get_period()
            );
        } else if (type == "hotp") {
            auto hotp = std::make_shared<HOTP>(
                uri.get_secret(),
                uri.get_algorithm(),
                uri.get_digits()
            );
            hotp->set_counter(uri.get_counter());
            return hotp;
        }
        throw std::invalid_argument("Invalid OTP type: " + type);
    }

private:
    static void parse_uri(const std::string& uri, OTP_URI& otp_uri) {
        // Basic URI format: otpauth://type/issuer:account?params
        if (uri.substr(0, 10) != "otpauth://") {
            throw std::invalid_argument("Invalid OTP URI format");
        }

        size_t type_end = uri.find('/', 10);
        if (type_end == std::string::npos) {
            throw std::invalid_argument("Invalid OTP URI format");
        }

        std::string type = uri.substr(10, type_end - 10);
        otp_uri.set_type(type);

        size_t path_end = uri.find('?', type_end);
        if (path_end == std::string::npos) {
            throw std::invalid_argument("Invalid OTP URI format");
        }

        std::string path = uri.substr(type_end + 1, path_end - type_end - 1);
        size_t colon_pos = path.find(':');
        if (colon_pos != std::string::npos) {
            otp_uri.set_issuer(path.substr(0, colon_pos));
            otp_uri.set_account(path.substr(colon_pos + 1));
        } else {
            otp_uri.set_account(path);
        }

        std::string params = uri.substr(path_end + 1);
        parse_params(params, otp_uri);
    }

    static void parse_params(const std::string& params, OTP_URI& otp_uri) {
        size_t pos = 0;
        while (pos < params.length()) {
            size_t eq_pos = params.find('=', pos);
            if (eq_pos == std::string::npos) break;

            std::string key = params.substr(pos, eq_pos - pos);
            size_t next_pos = params.find('&', eq_pos);
            std::string value = params.substr(eq_pos + 1, 
                next_pos == std::string::npos ? std::string::npos : next_pos - eq_pos - 1);

            if (key == "secret") {
                otp_uri.set_secret(value);
            } else if (key == "issuer") {
                otp_uri.set_issuer(value);
            } else if (key == "algorithm") {
                otp_uri.set_algorithm(value);
            } else if (key == "digits") {
                otp_uri.set_digits(std::stoul(value));
            } else if (key == "counter") {
                otp_uri.set_counter(std::stoul(value));
            } else if (key == "period") {
                otp_uri.set_period(std::stoul(value));
            }

            pos = next_pos == std::string::npos ? params.length() : next_pos + 1;
        }
    }
};

} // namespace cotp
