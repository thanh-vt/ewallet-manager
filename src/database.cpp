#include "database.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <iostream>
#include <filesystem>

Database* Database::instance = nullptr;

Database& Database::getInstance() {
    if (!instance) {
        instance = new Database();
    }
    return *instance;
}

Database::Database() {
    std::cout << "Database constructor started..." << std::endl;
    
    // Get the current executable path
    try {
        std::filesystem::path exePath = std::filesystem::current_path();
        std::cout << "Current path: " << exePath << std::endl;
        
        // Create database file path
        std::filesystem::path dbPath = exePath / "database.dat";
        std::cout << "Database path: " << dbPath << std::endl;
        
        // Try to load existing data first
        if (!loadFromFile()) {
            std::cout << "No existing database found. Creating new database..." << std::endl;
            
            try {
                std::cout << "Creating admin user..." << std::endl;
                // Create admin user if not exists
                auto admin = std::make_shared<User>("admin", "System Administrator", 
                    std::chrono::system_clock::now(), true);
                admin->setPassword("admin123"); // Default admin password
                
                std::cout << "Adding admin user to database..." << std::endl;
                if (!addUser(*admin)) {
                    std::cerr << "Failed to add admin user!" << std::endl;
                    return;
                }
                
                std::cout << "Creating admin wallet..." << std::endl;
                // Create admin wallet
                auto adminWallet = std::make_shared<Wallet>("ADMIN_WALLET", 1000000.0);
                
                std::cout << "Adding admin wallet to database..." << std::endl;
                if (!addWallet(*adminWallet)) {
                    std::cerr << "Failed to add admin wallet!" << std::endl;
                    return;
                }
                
                std::cout << "Setting admin wallet ID..." << std::endl;
                admin->setWalletId(adminWallet->getId());
                
                std::cout << "Saving initial database..." << std::endl;
                // Save the initial database
                if (!saveToFile()) {
                    std::cerr << "Failed to save initial database!" << std::endl;
                    return;
                }
                
                std::cout << "Initial database created successfully!" << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Error creating initial database: " << e.what() << std::endl;
            }
        } else {
            std::cout << "Existing database loaded successfully!" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in database initialization: " << e.what() << std::endl;
    }
}

Database::~Database() {
    std::cout << "Database destructor called..." << std::endl;
    saveToFile();
}

bool Database::addUser(const User& user) {
    std::cout << "Adding user: " << user.getUsername() << std::endl;
    std::lock_guard<std::mutex> lock(mutex_);
    auto username = user.getUsername();
    if (users.find(username) != users.end()) {
        std::cout << "User already exists: " << username << std::endl;
        return false;
    }
    users[username] = std::make_shared<User>(user);
    std::cout << "User added successfully: " << username << std::endl;
    return saveToFile();
}

bool Database::updateUser(const User& user) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto username = user.getUsername();
    if (users.find(username) == users.end()) {
        return false;
    }
    users[username] = std::make_shared<User>(user);
    return saveToFile(); // Save after updating user
}

bool Database::deleteUser(const std::string& username) {
    std::lock_guard<std::mutex> lock(mutex_);
    bool result = users.erase(username) > 0;
    if (result) {
        saveToFile(); // Save after deleting user
    }
    return result;
}

std::shared_ptr<User> Database::getUser(const std::string& username) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = users.find(username);
    return it != users.end() ? it->second : nullptr;
}

std::vector<std::shared_ptr<User>> Database::getAllUsers() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<User>> result;
    for (const auto& pair : users) {
        result.push_back(pair.second);
    }
    return result;
}

bool Database::addWallet(const Wallet& wallet) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto id = wallet.getId();
    if (wallets.find(id) != wallets.end()) {
        return false;
    }
    wallets[id] = std::make_shared<Wallet>(wallet);
    return saveToFile(); // Save after adding wallet
}

bool Database::updateWallet(const Wallet& wallet) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto id = wallet.getId();
    if (wallets.find(id) == wallets.end()) {
        return false;
    }
    wallets[id] = std::make_shared<Wallet>(wallet);
    return saveToFile(); // Save after updating wallet
}

bool Database::deleteWallet(const std::string& walletId) {
    std::lock_guard<std::mutex> lock(mutex_);
    bool result = wallets.erase(walletId) > 0;
    if (result) {
        saveToFile(); // Save after deleting wallet
    }
    return result;
}

std::shared_ptr<Wallet> Database::getWallet(const std::string& walletId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = wallets.find(walletId);
    return it != wallets.end() ? it->second : nullptr;
}

std::vector<std::shared_ptr<Wallet>> Database::getAllWallets() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<Wallet>> result;
    for (const auto& pair : wallets) {
        result.push_back(pair.second);
    }
    return result;
}

bool Database::addTransaction(const Transaction& transaction) {
    std::lock_guard<std::mutex> lock(mutex_);
    transactions_.push_back(transaction);
    return saveToFile(); // Save after adding transaction
}

std::vector<Transaction> Database::getWalletTransactions(const std::string& walletId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Transaction> result;
    for (const auto& transaction : transactions_) {
        if (transaction.fromWalletId == walletId || transaction.toWalletId == walletId) {
            result.push_back(transaction);
        }
    }
    return result;
}

void Database::serializeUser(std::ofstream& file, const User& user) {
    // Write username
    std::string username = user.getUsername();
    size_t len = username.length();
    file.write(reinterpret_cast<const char*>(&len), sizeof(len));
    file.write(username.c_str(), len);

    // Write fullname
    std::string fullname = user.getFullname();
    len = fullname.length();
    file.write(reinterpret_cast<const char*>(&len), sizeof(len));
    file.write(fullname.c_str(), len);

    // Write date of birth
    auto dob = user.getDateOfBirth();
    file.write(reinterpret_cast<const char*>(&dob), sizeof(dob));

    // Write password hash
    std::string passwordHash = user.getPasswordHash();
    len = passwordHash.length();
    file.write(reinterpret_cast<const char*>(&len), sizeof(len));
    file.write(passwordHash.c_str(), len);

    // Write 2FA info
    bool has2FA = user.has2FA();
    file.write(reinterpret_cast<const char*>(&has2FA), sizeof(has2FA));
    
    if (has2FA) {
        std::string secretKey = user.getSecretKey();
        len = secretKey.length();
        file.write(reinterpret_cast<const char*>(&len), sizeof(len));
        file.write(secretKey.c_str(), len);
    }

    // Write wallet ID
    std::string walletId = user.getWalletId();
    len = walletId.length();
    file.write(reinterpret_cast<const char*>(&len), sizeof(len));
    file.write(walletId.c_str(), len);

    // Write admin status
    bool isAdmin = user.isAdmin();
    file.write(reinterpret_cast<const char*>(&isAdmin), sizeof(isAdmin));
}

void Database::serializeWallet(std::ofstream& file, const Wallet& wallet) {
    // Write wallet ID
    std::string id = wallet.getId();
    size_t len = id.length();
    file.write(reinterpret_cast<const char*>(&len), sizeof(len));
    file.write(id.c_str(), len);

    // Write balance
    double balance = wallet.getBalance();
    file.write(reinterpret_cast<const char*>(&balance), sizeof(balance));

    // Write transactions
    const auto& transactions = wallet.getTransactionHistory();
    size_t numTransactions = transactions.size();
    file.write(reinterpret_cast<const char*>(&numTransactions), sizeof(numTransactions));
    
    for (const auto& transaction : transactions) {
        serializeTransaction(file, transaction);
    }
}

void Database::serializeTransaction(std::ofstream& file, const Transaction& transaction) {
    // Write transaction ID
    size_t len = transaction.id.length();
    file.write(reinterpret_cast<const char*>(&len), sizeof(len));
    file.write(transaction.id.c_str(), len);

    // Write from wallet ID
    len = transaction.fromWalletId.length();
    file.write(reinterpret_cast<const char*>(&len), sizeof(len));
    file.write(transaction.fromWalletId.c_str(), len);

    // Write to wallet ID
    len = transaction.toWalletId.length();
    file.write(reinterpret_cast<const char*>(&len), sizeof(len));
    file.write(transaction.toWalletId.c_str(), len);

    // Write amount
    file.write(reinterpret_cast<const char*>(&transaction.amount), sizeof(transaction.amount));

    // Write timestamp
    file.write(reinterpret_cast<const char*>(&transaction.timestamp), sizeof(transaction.timestamp));

    // Write status
    len = transaction.status.length();
    file.write(reinterpret_cast<const char*>(&len), sizeof(len));
    file.write(transaction.status.c_str(), len);

    // Write description
    len = transaction.description.length();
    file.write(reinterpret_cast<const char*>(&len), sizeof(len));
    file.write(transaction.description.c_str(), len);
}

User Database::deserializeUser(std::ifstream& file) {
    // Read username
    size_t len;
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    std::string username(len, '\0');
    file.read(&username[0], len);

    // Read fullname
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    std::string fullname(len, '\0');
    file.read(&fullname[0], len);

    // Read date of birth
    std::chrono::system_clock::time_point dob;
    file.read(reinterpret_cast<char*>(&dob), sizeof(dob));

    // Create user
    User user(username, fullname, dob);

    // Read password hash
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    std::string passwordHash(len, '\0');
    file.read(&passwordHash[0], len);
    user.setPasswordHash(passwordHash);

    // Read 2FA info
    bool has2FA;
    file.read(reinterpret_cast<char*>(&has2FA), sizeof(has2FA));
    
    if (has2FA) {
        file.read(reinterpret_cast<char*>(&len), sizeof(len));
        std::string secretKey(len, '\0');
        file.read(&secretKey[0], len);
        user.setSecretKey(secretKey);
        user.enable2FA();
    }

    // Read wallet ID
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    std::string walletId(len, '\0');
    file.read(&walletId[0], len);
    user.setWalletId(walletId);

    // Read admin status
    bool isAdmin;
    file.read(reinterpret_cast<char*>(&isAdmin), sizeof(isAdmin));
    if (isAdmin) {
        // Set admin status if needed
    }

    return user;
}

Wallet Database::deserializeWallet(std::ifstream& file) {
    // Read wallet ID
    size_t len;
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    std::string id(len, '\0');
    file.read(&id[0], len);

    // Read balance
    double balance;
    file.read(reinterpret_cast<char*>(&balance), sizeof(balance));

    // Create wallet
    Wallet wallet(id, balance);

    // Read transactions
    size_t numTransactions;
    file.read(reinterpret_cast<char*>(&numTransactions), sizeof(numTransactions));
    
    for (size_t i = 0; i < numTransactions; ++i) {
        Transaction transaction = deserializeTransaction(file);
        wallet.addTransaction(transaction);
    }

    return wallet;
}

Transaction Database::deserializeTransaction(std::ifstream& file) {
    Transaction transaction;

    // Read transaction ID
    size_t len;
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    transaction.id.resize(len);
    file.read(&transaction.id[0], len);

    // Read from wallet ID
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    transaction.fromWalletId.resize(len);
    file.read(&transaction.fromWalletId[0], len);

    // Read to wallet ID
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    transaction.toWalletId.resize(len);
    file.read(&transaction.toWalletId[0], len);

    // Read amount
    file.read(reinterpret_cast<char*>(&transaction.amount), sizeof(transaction.amount));

    // Read timestamp
    file.read(reinterpret_cast<char*>(&transaction.timestamp), sizeof(transaction.timestamp));

    // Read status
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    transaction.status.resize(len);
    file.read(&transaction.status[0], len);

    // Read description
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    transaction.description.resize(len);
    file.read(&transaction.description[0], len);

    return transaction;
}

bool Database::saveToFile() {
    std::cout << "Saving database to file..." << std::endl;
    std::lock_guard<std::mutex> lock(mutex_);
    
    // First, try to create a simple test file to verify write permissions
    std::cout << "Testing write permissions..." << std::endl;
    {
        std::ofstream testFile("test_write.tmp");
        if (!testFile) {
            std::cerr << "Error: No write permission in current directory" << std::endl;
            return false;
        }
        testFile << "test" << std::endl;
        testFile.close();
        std::filesystem::remove("test_write.tmp");
    }
    
    std::cout << "Write permissions verified. Proceeding with database save..." << std::endl;
    
    try {
        // Open file in text mode first to test
        std::cout << "Opening file in text mode: " << DB_FILE << std::endl;
        std::ofstream file(DB_FILE);
        if (!file) {
            std::cerr << "Error: Could not open file in text mode" << std::endl;
            return false;
        }
        file.close();
        
        // Now open in binary mode
        std::cout << "Opening file in binary mode..." << std::endl;
        file.open(DB_FILE, std::ios::binary | std::ios::trunc);
        if (!file) {
            std::cerr << "Error: Could not open file in binary mode" << std::endl;
            return false;
        }

        // Write a simple header to verify file writing
        std::cout << "Writing file header..." << std::endl;
        const char header[] = "EWALLET_DB";
        file.write(header, sizeof(header) - 1);
        if (file.fail()) {
            std::cerr << "Error writing file header" << std::endl;
            file.close();
            return false;
        }

        // Write number of users
        size_t numUsers = users.size();
        std::cout << "Writing " << numUsers << " users..." << std::endl;
        file.write(reinterpret_cast<const char*>(&numUsers), sizeof(numUsers));
        if (file.fail()) {
            std::cerr << "Error writing number of users" << std::endl;
            file.close();
            return false;
        }

        // Write users
        for (const auto& pair : users) {
            std::cout << "Writing user: " << pair.first << std::endl;
            serializeUser(file, *pair.second);
            if (file.fail()) {
                std::cerr << "Error writing user: " << pair.first << std::endl;
                file.close();
                return false;
            }
        }

        // Write number of wallets
        size_t numWallets = wallets.size();
        std::cout << "Writing " << numWallets << " wallets..." << std::endl;
        file.write(reinterpret_cast<const char*>(&numWallets), sizeof(numWallets));
        if (file.fail()) {
            std::cerr << "Error writing number of wallets" << std::endl;
            file.close();
            return false;
        }

        // Write wallets
        for (const auto& pair : wallets) {
            std::cout << "Writing wallet: " << pair.first << std::endl;
            serializeWallet(file, *pair.second);
            if (file.fail()) {
                std::cerr << "Error writing wallet: " << pair.first << std::endl;
                file.close();
                return false;
            }
        }

        // Write transactions
        size_t numTransactions = transactions_.size();
        std::cout << "Writing " << numTransactions << " transactions..." << std::endl;
        file.write(reinterpret_cast<const char*>(&numTransactions), sizeof(numTransactions));
        if (file.fail()) {
            std::cerr << "Error writing number of transactions" << std::endl;
            file.close();
            return false;
        }

        for (const auto& transaction : transactions_) {
            std::cout << "Writing transaction: " << transaction.id << std::endl;
            serializeTransaction(file, transaction);
            if (file.fail()) {
                std::cerr << "Error writing transaction: " << transaction.id << std::endl;
                file.close();
                return false;
            }
        }

        // Flush and close
        std::cout << "Flushing and closing file..." << std::endl;
        file.flush();
        file.close();
        
        if (file.fail()) {
            std::cerr << "Error during file close" << std::endl;
            return false;
        }

        std::cout << "Database saved successfully to: " << DB_FILE << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error saving database: " << e.what() << std::endl;
        return false;
    }
}

bool Database::loadFromFile() {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        std::ifstream file(DB_FILE, std::ios::binary);
        if (!file) {
            std::cerr << "Error: Could not open database file for reading: " << DB_FILE << std::endl;
            return false;
        }

        // Clear existing data
        users.clear();
        wallets.clear();
        transactions_.clear();

        // Read number of users
        size_t numUsers;
        file.read(reinterpret_cast<char*>(&numUsers), sizeof(numUsers));

        // Read users
        for (size_t i = 0; i < numUsers; ++i) {
            User user = deserializeUser(file);
            users[user.getUsername()] = std::make_shared<User>(user);
        }

        // Read number of wallets
        size_t numWallets;
        file.read(reinterpret_cast<char*>(&numWallets), sizeof(numWallets));

        // Read wallets
        for (size_t i = 0; i < numWallets; ++i) {
            Wallet wallet = deserializeWallet(file);
            wallets[wallet.getId()] = std::make_shared<Wallet>(wallet);
        }

        // Read transactions
        size_t numTransactions;
        file.read(reinterpret_cast<char*>(&numTransactions), sizeof(numTransactions));
        for (size_t i = 0; i < numTransactions; ++i) {
            transactions_.push_back(deserializeTransaction(file));
        }

        file.close();
        std::cout << "Database loaded successfully from: " << DB_FILE << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error loading database: " << e.what() << std::endl;
        return false;
    }
} 