#pragma once

#include <string>
#include <chrono>
#include <memory>
#include <optional>
#include <vector>

class User {
public:
    User(const std::string& username, 
         const std::string& fullname,
         const std::chrono::system_clock::time_point& dob,
         bool isAdmin = false);

    // Getters
    const std::string& getUsername() const { return username_; }
    const std::string& getFullname() const { return fullname_; }
    const std::chrono::system_clock::time_point& getDateOfBirth() const { return dateOfBirth_; }
    bool isAdmin() const { return isAdmin_; }
    bool has2FA() const { return has2FA_; }
    const std::string& getWalletId() const { return walletId_; }
    const std::string& getPasswordHash() const { return passwordHash_; }
    const std::string& getSecretKey() const { return secretKey_; }
    const std::string& getPassword() const;

    // Setters
    void setPassword(const std::string& newPassword);
    void setPasswordHash(const std::string& hash) { passwordHash_ = hash; }
    void setSecretKey(const std::string& key) { secretKey_ = key; }
    void enable2FA();
    void disable2FA();
    void setWalletId(const std::string& walletId);

    // Authentication
    bool verifyPassword(const std::string& password) const;
    bool verify2FA(const std::string& otp) const;

    // Static methods
    static std::string generatePassword();
    static std::string hashPassword(const std::string& password);

private:
    std::string username_;
    std::string fullname_;
    std::chrono::system_clock::time_point dateOfBirth_;
    std::string passwordHash_;
    bool isAdmin_;
    bool has2FA_;
    std::string secretKey_; // For 2FA
    std::string walletId_;
}; 