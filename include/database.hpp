#pragma once

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <chrono>
#include <filesystem>
#include "user.hpp"
#include "wallet.hpp"
#include "transaction.hpp"

class Database {
private:
    static Database* instance;
    std::map<std::string, std::shared_ptr<User>> users;
    std::map<std::string, std::shared_ptr<Wallet>> wallets;
    std::vector<Transaction> transactions_;

    // File paths
    std::string USERS_FILE;
    std::string WALLETS_FILE;
    std::string TRANSACTIONS_FILE;

    // Last modification times
    std::filesystem::file_time_type lastUsersModification;
    std::filesystem::file_time_type lastWalletsModification;
    std::filesystem::file_time_type lastTransactionsModification;

    // Private constructor for singleton
    Database();
    ~Database();

    // Helper functions
    bool isFileModified();
    void serializeUser(std::ofstream& file, const User& user);
    void serializeWallet(std::ofstream& file, const Wallet& wallet);
    void serializeTransaction(std::ofstream& file, const Transaction& transaction);
    User deserializeUser(std::ifstream& file);
    Wallet deserializeWallet(std::ifstream& file);
    Transaction deserializeTransaction(std::ifstream& file);

    // File operations
    bool saveUsersToFile();
    bool saveWalletsToFile();
    bool saveTransactionsToFile();
    bool loadUsersFromFile();
    bool loadWalletsFromFile();
    bool loadTransactionsFromFile();

public:
    // Singleton instance
    static Database& getInstance();

    // File operations
    bool saveToFiles();
    bool loadFromFiles();

    // User operations
    bool addUser(const User& user);
    bool updateUser(const User& user);
    bool deleteUser(const std::string& username);
    std::shared_ptr<User> getUser(const std::string& username);
    std::vector<std::shared_ptr<User>> getAllUsers();

    // Wallet operations
    bool addWallet(const Wallet& wallet);
    bool updateWallet(const Wallet& wallet);
    bool deleteWallet(const std::string& walletId);
    std::shared_ptr<Wallet> getWallet(const std::string& walletId);
    std::vector<std::shared_ptr<Wallet>> getAllWallets();

    // Transaction operations
    bool addTransaction(const Transaction& transaction);
    std::vector<Transaction> getWalletTransactions(const std::string& walletId);

    // Database path operations
    void setBasePath(const std::filesystem::path& path);
}; 