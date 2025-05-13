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
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <stdexcept>
#include <cmath>
#include <ctime>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace cotp {

typedef std::function<std::vector<char>(std::vector<char> const&, std::vector<char> const&)> OTP_algorithm_ptr;

struct Algo_info {
	std::string name;
	OTP_algorithm_ptr algo;
	size_t bits;
};

enum class OTP_type {
	OTP,
	TOTP,
	HOTP
};

class OTP_URI;

class OTP {
	friend class TOTP;
	friend class HOTP;

	public:
		static const std::string base32_chars;
		static std::map<std::string, Algo_info> otp_algorithm_map;

		static const size_t OTP_MIN_DIGITS = 6;
		static const size_t OTP_MAX_DIGITS = 8;

		OTP(std::string const& base32_secret, std::string const& algo, size_t digits);
		OTP(std::string const& base32_secret, size_t bits, OTP_algorithm_ptr algo, std::string const& digest_algo_name, size_t digits);
		virtual ~OTP() = default;

		OTP(const OTP&) = delete;                  // copy constructor
		OTP& operator=(const OTP& other) = delete; // assignment operator
		OTP(OTP&& other);                          // move constructor
		OTP& operator=(OTP&& other);               // move assignment operator

		void set_issuer(std::string const& value);
		void set_account(std::string const& value);
		std::string const& get_issuer() const;
		std::string const& get_account() const;

		std::string generate(uint64_t input) const;
		std::vector<char> byte_secret() const;
		static std::vector<char> to_bytes(uint64_t value);
		static std::string random_base32(size_t len = 0);

		virtual std::string build_uri() const;
		std::string build_uri(std::string const& otp_type, std::map<std::string, std::string> const& additional_args) const;

		virtual std::string code() const = 0;

		virtual std::ostream& print(std::ostream& os) const;

		static bool register_hmac_algo(std::string const& name, OTP_algorithm_ptr const algo, size_t bits);

	protected:
		size_t m_digits;
		size_t m_bits;
		OTP_type m_method;
		OTP_algorithm_ptr m_algo;
		std::string m_digest_algo_name;
		std::string m_base32_secret;
		std::string m_issuer;
		std::string m_account;
};

typedef std::shared_ptr<OTP> OTP_ptr;

class TOTP : public OTP {
	friend std::ostream& operator<<(std::ostream& os, TOTP const& obj);

	public:
		TOTP(std::string const& base32_secret, std::string const& algo, size_t digits, size_t interval);
		TOTP(std::string const& base32_secret, size_t bits, OTP_algorithm_ptr algo, std::string const& digest_algo_name, size_t digits, size_t interval);
		~TOTP() = default;

		TOTP(const TOTP&) = delete;                  // copy constructor
		TOTP& operator=(const TOTP& other) = delete; // assignment operator
		TOTP(TOTP&& other);                          // move constructor
		TOTP& operator=(TOTP&& other);               // move assignment operator

		static OTP_ptr create(OTP_URI const& uri);

		bool compare(std::string const& key, size_t increment, uint64_t for_time) const;
		bool compare(uint64_t key, size_t increment, uint64_t for_time) const;
		std::string code_at(uint64_t for_time, size_t counter_offset) const;
		std::string code() const override;
		bool verify(std::string const& key, uint64_t for_time, size_t valid_window) const;
		bool verify(uint64_t key, uint64_t for_time, size_t valid_window) const;
		bool verify(std::string const& key, size_t valid_window) const;
		bool verify(uint64_t key, size_t valid_window) const;
		unsigned int valid_until(uint64_t for_time, size_t valid_window) const;
		unsigned int seconds_to_next_code(uint64_t for_time) const;
		unsigned int seconds_to_next_code() const;
		int timecode(uint64_t for_time) const;
		std::string build_uri() const override;
		std::ostream& print(std::ostream& os) const;

	private:
		size_t m_interval;
};

class HOTP : public OTP {
	friend std::ostream& operator<<(std::ostream& os, HOTP const& obj);

	public:
		HOTP(std::string const& base32_secret, std::string const& algo, size_t digits);
		HOTP(std::string const& base32_secret, size_t bits, OTP_algorithm_ptr algo, std::string const& digest_algo_name, size_t digits);
		~HOTP() = default;

		HOTP(const HOTP&) = delete;                  // copy constructor
		HOTP& operator=(const HOTP& other) = delete; // assignment operator
		HOTP(HOTP&& other);                          // move constructor
		HOTP& operator=(HOTP&& other);               // move assignment operator

		static OTP_ptr create(OTP_URI const& uri);

		void set_counter(size_t value);
		size_t get_counter() const;
		bool compare(std::string const& key) const;
		bool compare(uint64_t key) const;
		std::string code() const override;
		std::string code_at(size_t counter) const;
		bool verify(std::string const& key) const;
		bool verify(uint64_t key) const;
		std::string build_uri() const override;
		std::ostream& print(std::ostream& os) const;

	private:
		size_t m_counter;
};

}
