#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <memory>

struct Transaction {
    std::string id;
    std::string fromWalletId;
    std::string toWalletId;
    double amount;
    std::chrono::system_clock::time_point timestamp;
    std::string status; // "completed", "failed", "pending"
    std::string description;
};

class Wallet {
public:
    Wallet(const std::string& id, double initialBalance = 0.0);

    // Getters
    const std::string& getId() const { return id_; }
    double getBalance() const { return balance_; }
    const std::vector<Transaction>& getTransactionHistory() const { return transactions_; }

    // Transaction methods
    bool transfer(Wallet& destination, double amount, const std::string& description = "");
    void addTransaction(const Transaction& transaction);
    
    // Balance management
    void addBalance(double amount);
    bool deductBalance(double amount);

    std::string generateTransactionId();

private:
    std::string id_;
    double balance_;
    std::vector<Transaction> transactions_;
}; 