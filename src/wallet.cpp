#include "wallet.hpp"
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>

Wallet::Wallet(const std::string& id, double initialBalance)
    : id_(id)
    , balance_(initialBalance) {
}

bool Wallet::transfer(Wallet& destination, double amount, const std::string& description) {
    if (amount <= 0 || amount > balance_) {
        return false;
    }

    // Create transaction record
    Transaction transaction;
    transaction.id = generateTransactionId();
    transaction.fromWalletId = id_;
    transaction.toWalletId = destination.getId();
    transaction.amount = amount;
    transaction.timestamp = std::chrono::system_clock::now();
    transaction.description = description;

    try {
        // Deduct from source
        if (!deductBalance(amount)) {
            transaction.status = "failed";
            addTransaction(transaction);
            return false;
        }

        // Add to destination
        destination.addBalance(amount);
        transaction.status = "completed";
        addTransaction(transaction);
        destination.addTransaction(transaction);
        return true;
    } catch (...) {
        // Rollback
        addBalance(amount);
        transaction.status = "failed";
        addTransaction(transaction);
        return false;
    }
}

void Wallet::addTransaction(const Transaction& transaction) {
    transactions_.push_back(transaction);
}

void Wallet::addBalance(double amount) {
    if (amount > 0) {
        balance_ += amount;
    }
}

bool Wallet::deductBalance(double amount) {
    if (amount > 0 && amount <= balance_) {
        balance_ -= amount;
        return true;
    }
    return false;
}

std::string Wallet::generateTransactionId() {
    auto now = std::chrono::system_clock::now();
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 9999);
    
    std::stringstream ss;
    ss << std::hex << now_ms.count() << std::setw(4) << std::setfill('0') << dis(gen);
    return ss.str();
} 