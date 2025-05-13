#pragma once

#include "user.hpp"
#include "wallet.hpp"
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <fstream>
#include <filesystem>

class Database {
    private:
        static Database* instance;
        Database();
        ~Database();

        std::unordered_map<std::string, std::shared_ptr<User>> users;
        std::unordered_map<std::string, std::shared_ptr<Wallet>> wallets;
        std::vector<Transaction> transactions_;
        std::string DB_FILE;
        std::filesystem::file_time_type lastFileModification;

        // Helper function to check if file has been modified
        bool isFileModified();

        // Binary serialization methods
        void serializeUser(std::ofstream& file, const User& user);
        void serializeWallet(std::ofstream& file, const Wallet& wallet);
        void serializeTransaction(std::ofstream& file, const Transaction& transaction);
        
        User deserializeUser(std::ifstream& file);
        Wallet deserializeWallet(std::ifstream& file);
        Transaction deserializeTransaction(std::ifstream& file);

    public:
        static Database& getInstance();
        
        // Prevent copying
        Database(const Database&) = delete;
        Database& operator=(const Database&) = delete;

        // User management
        bool addUser(const User& user);
        bool updateUser(const User& user);
        bool deleteUser(const std::string& username);
        std::shared_ptr<User> getUser(const std::string& username);
        std::vector<std::shared_ptr<User>> getAllUsers();

        // Wallet management
        bool addWallet(const Wallet& wallet);
        bool updateWallet(const Wallet& wallet);
        bool deleteWallet(const std::string& walletId);
        std::shared_ptr<Wallet> getWallet(const std::string& walletId);
        std::vector<std::shared_ptr<Wallet>> getAllWallets();

        // Transaction management
        bool addTransaction(const Transaction& transaction);
        std::vector<Transaction> getWalletTransactions(const std::string& walletId);

        // Database operations
        bool saveToFile();
        bool loadFromFile();
}; 