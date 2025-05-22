#pragma once

#include <string>
#include <chrono>

class Transaction {
public:
    std::string id;
    std::string fromWalletId;
    std::string toWalletId;
    double amount;
    std::chrono::system_clock::time_point timestamp;
    std::string status;
    std::string description;

    Transaction() = default;

    Transaction(const std::string& id,
               const std::string& fromWalletId,
               const std::string& toWalletId,
               double amount,
               const std::string& status = "pending",
               const std::string& description = "")
        : id(id)
        , fromWalletId(fromWalletId)
        , toWalletId(toWalletId)
        , amount(amount)
        , timestamp(std::chrono::system_clock::now())
        , status(status)
        , description(description) {}

    // Getters
    const std::string& getId() const { return id; }
    const std::string& getFromWalletId() const { return fromWalletId; }
    const std::string& getToWalletId() const { return toWalletId; }
    double getAmount() const { return amount; }
    const std::chrono::system_clock::time_point& getTimestamp() const { return timestamp; }
    const std::string& getStatus() const { return status; }
    const std::string& getDescription() const { return description; }

    // Setters
    void setStatus(const std::string& newStatus) { status = newStatus; }
    void setDescription(const std::string& newDescription) { description = newDescription; }
}; 