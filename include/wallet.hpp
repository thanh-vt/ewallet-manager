#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include "transaction.hpp"

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