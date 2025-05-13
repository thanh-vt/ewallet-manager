#include "database.hpp"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <filesystem>

Database* Database::instance = nullptr;

// Helper function to check if file has been modified
bool Database::isFileModified() {
    try {
        if (!std::filesystem::exists(DB_FILE)) {
            throw std::runtime_error("Database file not found: " + DB_FILE);
        }

        auto lastWriteTime = std::filesystem::last_write_time(DB_FILE);
        if (lastWriteTime != lastFileModification) {
            lastFileModification = lastWriteTime;
            return true;
        }
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Critical error in isFileModified: " << e.what() << std::endl;
        throw; // Re-throw the exception to crash the program
    }
}

Database& Database::getInstance() {
    if (!instance) {
        instance = new Database();
    }
    return *instance;
}

Database::Database() {
    std::cout << "Database constructor started..." << std::endl;
    
    try {
        // Get the executable directory
        std::filesystem::path exePath = std::filesystem::current_path();
        std::cout << "Executable path: " << exePath << std::endl;
        
        // Create database file path in executable directory
        DB_FILE = (exePath / "database.dat").string();
        std::cout << "Database path: " << DB_FILE << std::endl;

        // Check if we can write to the directory
        std::string testFile = (exePath / "test_write.tmp").string();
        std::cout << "Testing write permissions with file: " << testFile << std::endl;
        {
            std::ofstream test(testFile);
            if (!test) {
                std::cerr << "Error: Cannot write to directory: " << exePath << std::endl;
                return;
            }
            test << "test" << std::endl;
            test.close();
            std::filesystem::remove(testFile);
        }
        std::cout << "Write permissions verified" << std::endl;
        
        // Try to load existing data
        bool loadSuccess = loadFromFile();
        
        // If loading failed or database is empty, create admin user and wallet
        if (!loadSuccess || (users.empty() && wallets.empty())) {
            std::cout << "Creating new database with admin user..." << std::endl;
            
            try {
                std::cout << "Creating admin user..." << std::endl;
                // Create admin user if not exists
                auto admin = std::make_shared<User>("admin", "System Administrator", 
                    std::chrono::system_clock::now(), true);
                admin->setPassword("admin123"); // Default admin password
                
                std::cout << "Adding admin user to database..." << std::endl;
                users["admin"] = admin;  // Add directly to users map
                
                std::cout << "Creating admin wallet..." << std::endl;
                // Create admin wallet
                auto adminWallet = std::make_shared<Wallet>("ADMIN_WALLET", 1000000.0);
                
                std::cout << "Adding admin wallet to database..." << std::endl;
                wallets["ADMIN_WALLET"] = adminWallet;  // Add directly to wallets map
                
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
    
    // Only check for file modifications if we're not in initialization
    if (!users.empty() && isFileModified()) {
        std::cout << "Database file was modified, reloading..." << std::endl;
        if (!loadFromFile()) {
            std::cerr << "Failed to reload database" << std::endl;
            return false;
        }
    }

    auto username = user.getUsername();
    if (users.find(username) != users.end()) {
        std::cout << "User already exists: " << username << std::endl;
        return false;
    }

    // Add the user to the in-memory map
    users[username] = std::make_shared<User>(user);
    std::cout << "User added to memory: " << username << std::endl;

    // Save changes to file
    if (!saveToFile()) {
        std::cerr << "Failed to save database after adding user" << std::endl;
        // Remove the user from memory if save failed
        users.erase(username);
        return false;
    }

    std::cout << "User successfully added and saved: " << username << std::endl;
    return true;
}

bool Database::updateUser(const User& user) {
    if (isFileModified()) {
        if (!loadFromFile()) {
            return false;
        }
    }

    auto username = user.getUsername();
    if (users.find(username) == users.end()) {
        return false;
    }
    users[username] = std::make_shared<User>(user);
    return saveToFile();
}

bool Database::deleteUser(const std::string& username) {
    if (isFileModified()) {
        if (!loadFromFile()) {
            return false;
        }
    }

    bool result = users.erase(username) > 0;
    if (result) {
        saveToFile();
    }
    return result;
}

std::shared_ptr<User> Database::getUser(const std::string& username) {
    auto it = users.find(username);
    return it != users.end() ? it->second : nullptr;
}

std::vector<std::shared_ptr<User>> Database::getAllUsers() {
    std::vector<std::shared_ptr<User>> result;
    for (const auto& pair : users) {
        result.push_back(pair.second);
    }
    return result;
}

bool Database::addWallet(const Wallet& wallet) {
    std::cout << "Adding wallet: " << wallet.getId() << std::endl;
    
    // Only check for file modifications if we're not in initialization
    if (!wallets.empty() && isFileModified()) {
        std::cout << "Database file was modified, reloading..." << std::endl;
        if (!loadFromFile()) {
            std::cerr << "Failed to reload database" << std::endl;
            return false;
        }
    }

    auto id = wallet.getId();
    if (wallets.find(id) != wallets.end()) {
        std::cout << "Wallet already exists: " << id << std::endl;
        return false;
    }

    // Add the wallet to the in-memory map
    wallets[id] = std::make_shared<Wallet>(wallet);
    std::cout << "Wallet added to memory: " << id << std::endl;

    // Save changes to file
    if (!saveToFile()) {
        std::cerr << "Failed to save database after adding wallet" << std::endl;
        // Remove the wallet from memory if save failed
        wallets.erase(id);
        return false;
    }

    std::cout << "Wallet successfully added and saved: " << id << std::endl;
    return true;
}

bool Database::updateWallet(const Wallet& wallet) {
    if (isFileModified()) {
        if (!loadFromFile()) {
            return false;
        }
    }

    auto id = wallet.getId();
    if (wallets.find(id) == wallets.end()) {
        return false;
    }
    wallets[id] = std::make_shared<Wallet>(wallet);
    return saveToFile();
}

bool Database::deleteWallet(const std::string& walletId) {
    if (isFileModified()) {
        if (!loadFromFile()) {
            return false;
        }
    }

    bool result = wallets.erase(walletId) > 0;
    if (result) {
        saveToFile();
    }
    return result;
}

std::shared_ptr<Wallet> Database::getWallet(const std::string& walletId) {
    auto it = wallets.find(walletId);
    return it != wallets.end() ? it->second : nullptr;
}

std::vector<std::shared_ptr<Wallet>> Database::getAllWallets() {
    std::vector<std::shared_ptr<Wallet>> result;
    for (const auto& pair : wallets) {
        result.push_back(pair.second);
    }
    return result;
}

bool Database::addTransaction(const Transaction& transaction) {
    if (isFileModified()) {
        if (!loadFromFile()) {
            return false;
        }
    }

    transactions_.push_back(transaction);
    return saveToFile();
}

std::vector<Transaction> Database::getWalletTransactions(const std::string& walletId) {
    std::vector<Transaction> result;
    for (const auto& transaction : transactions_) {
        if (transaction.fromWalletId == walletId || transaction.toWalletId == walletId) {
            result.push_back(transaction);
        }
    }
    return result;
}

void Database::serializeUser(std::ofstream& file, const User& user) {
    try {
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

        // Write admin status
        bool isAdmin = user.isAdmin();
        file.write(reinterpret_cast<const char*>(&isAdmin), sizeof(isAdmin));

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

        if (file.fail()) {
            throw std::runtime_error("Failed to write user data");
        }
    } catch (const std::exception& e) {
        std::cerr << "Error serializing user: " << e.what() << std::endl;
        throw;
    }
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
    try {
        // Read username
        size_t len;
        if (!file.read(reinterpret_cast<char*>(&len), sizeof(len)) || len > 1000) {
            throw std::runtime_error("Invalid username length");
        }
        std::string username(len, '\0');
        if (!file.read(&username[0], len)) {
            throw std::runtime_error("Failed to read username");
        }

        // Read fullname
        if (!file.read(reinterpret_cast<char*>(&len), sizeof(len)) || len > 1000) {
            throw std::runtime_error("Invalid fullname length");
        }
        std::string fullname(len, '\0');
        if (!file.read(&fullname[0], len)) {
            throw std::runtime_error("Failed to read fullname");
        }

        // Read date of birth
        std::chrono::system_clock::time_point dob;
        if (!file.read(reinterpret_cast<char*>(&dob), sizeof(dob))) {
            throw std::runtime_error("Failed to read date of birth");
        }

        // Read admin status
        bool isAdmin;
        if (!file.read(reinterpret_cast<char*>(&isAdmin), sizeof(isAdmin))) {
            throw std::runtime_error("Failed to read admin status");
        }

        // Create user with admin status
        User user(username, fullname, dob, isAdmin);

        // Read password hash
        if (!file.read(reinterpret_cast<char*>(&len), sizeof(len)) || len > 1000) {
            throw std::runtime_error("Invalid password hash length");
        }
        std::string passwordHash(len, '\0');
        if (!file.read(&passwordHash[0], len)) {
            throw std::runtime_error("Failed to read password hash");
        }
        user.setPasswordHash(passwordHash);

        // Read 2FA info
        bool has2FA;
        if (!file.read(reinterpret_cast<char*>(&has2FA), sizeof(has2FA))) {
            throw std::runtime_error("Failed to read 2FA status");
        }
        
        if (has2FA) {
            if (!file.read(reinterpret_cast<char*>(&len), sizeof(len)) || len > 1000) {
                throw std::runtime_error("Invalid secret key length");
            }
            std::string secretKey(len, '\0');
            if (!file.read(&secretKey[0], len)) {
                throw std::runtime_error("Failed to read secret key");
            }
            user.setSecretKey(secretKey);
            user.enable2FA();
        }

        // Read wallet ID
        if (!file.read(reinterpret_cast<char*>(&len), sizeof(len)) || len > 1000) {
            throw std::runtime_error("Invalid wallet ID length");
        }
        std::string walletId(len, '\0');
        if (!file.read(&walletId[0], len)) {
            throw std::runtime_error("Failed to read wallet ID");
        }
        user.setWalletId(walletId);

        return user;
    } catch (const std::exception& e) {
        std::cerr << "Error deserializing user: " << e.what() << std::endl;
        throw;
    }
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
    try {
        std::cout << "Attempting to save database to: " << DB_FILE << std::endl;
        
        // Create a temporary file
        std::string tempFile = DB_FILE + ".tmp";
        std::cout << "Creating temporary file: " << tempFile << std::endl;
        
        std::ofstream file(tempFile, std::ios::binary | std::ios::trunc);
        if (!file) {
            std::cerr << "Failed to open temporary file for writing: " << tempFile << std::endl;
            return false;
        }

        // Write magic number and version
        const uint32_t MAGIC = 0x4557414C;  // "EWAL" in hex
        const uint32_t VERSION = 1;
        file.write(reinterpret_cast<const char*>(&MAGIC), sizeof(MAGIC));
        file.write(reinterpret_cast<const char*>(&VERSION), sizeof(VERSION));
        if (file.fail()) {
            std::cerr << "Error writing file header" << std::endl;
            file.close();
            std::filesystem::remove(tempFile);
            return false;
        }

        // Write number of users
        size_t numUsers = users.size();
        std::cout << "Writing " << numUsers << " users..." << std::endl;
        file.write(reinterpret_cast<const char*>(&numUsers), sizeof(numUsers));
        if (file.fail()) {
            std::cerr << "Error writing number of users" << std::endl;
            file.close();
            std::filesystem::remove(tempFile);
            return false;
        }

        // Write users
        for (const auto& pair : users) {
            std::cout << "Writing user: " << pair.first << std::endl;
            serializeUser(file, *pair.second);
            if (file.fail()) {
                std::cerr << "Error writing user: " << pair.first << std::endl;
                file.close();
                std::filesystem::remove(tempFile);
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
            std::filesystem::remove(tempFile);
            return false;
        }

        // Write wallets
        for (const auto& pair : wallets) {
            std::cout << "Writing wallet: " << pair.first << std::endl;
            serializeWallet(file, *pair.second);
            if (file.fail()) {
                std::cerr << "Error writing wallet: " << pair.first << std::endl;
                file.close();
                std::filesystem::remove(tempFile);
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
            std::filesystem::remove(tempFile);
            return false;
        }

        for (const auto& transaction : transactions_) {
            std::cout << "Writing transaction: " << transaction.id << std::endl;
            serializeTransaction(file, transaction);
            if (file.fail()) {
                std::cerr << "Error writing transaction: " << transaction.id << std::endl;
                file.close();
                std::filesystem::remove(tempFile);
                return false;
            }
        }

        // Flush and close the output file
        file.flush();
        file.close();
        
        if (file.fail()) {
            std::cerr << "Error during file close" << std::endl;
            std::filesystem::remove(tempFile);
            return false;
        }

        // Calculate checksum using a separate input stream
        std::ifstream checkFile(tempFile, std::ios::binary);
        if (!checkFile) {
            std::cerr << "Failed to open file for checksum calculation" << std::endl;
            std::filesystem::remove(tempFile);
            return false;
        }

        uint32_t checksum = 0;
        char buffer[4096];
        while (checkFile) {
            checkFile.read(buffer, sizeof(buffer));
            std::streamsize count = checkFile.gcount();
            for (std::streamsize i = 0; i < count; ++i) {
                checksum = (checksum << 8) | (static_cast<unsigned char>(buffer[i]));
            }
        }
        checkFile.close();

        // Append checksum to the file
        std::ofstream appendFile(tempFile, std::ios::binary | std::ios::app);
        if (!appendFile) {
            std::cerr << "Failed to open file for checksum writing" << std::endl;
            std::filesystem::remove(tempFile);
            return false;
        }
        appendFile.write(reinterpret_cast<const char*>(&checksum), sizeof(checksum));
        appendFile.close();

        if (appendFile.fail()) {
            std::cerr << "Error writing checksum" << std::endl;
            std::filesystem::remove(tempFile);
            return false;
        }

        // Replace the old file with the new one
        if (std::filesystem::exists(DB_FILE)) {
            std::filesystem::remove(DB_FILE);
        }
        std::filesystem::rename(tempFile, DB_FILE);
        lastFileModification = std::filesystem::last_write_time(DB_FILE);
        std::cout << "Database saved successfully to: " << DB_FILE << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error saving database: " << e.what() << std::endl;
        return false;
    }
}

bool Database::loadFromFile() {
    try {
        if (!std::filesystem::exists(DB_FILE)) {
            std::cout << "Database file not found. Creating new database..." << std::endl;
            return false;
        }

        std::cout << "Opening database file: " << DB_FILE << std::endl;
        std::ifstream file(DB_FILE, std::ios::binary);
        if (!file) {
            std::cerr << "Failed to open database file for reading: " << DB_FILE << std::endl;
            return false;
        }

        // Check if file is empty
        file.seekg(0, std::ios::end);
        if (file.tellg() == 0) {
            std::cout << "Database file is empty. Creating new database..." << std::endl;
            file.close();
            return false;
        }
        file.seekg(0, std::ios::beg);

        // Read and verify magic number
        uint32_t magic;
        file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        if (file.fail() || magic != 0x4557414C) {  // "EWAL" in hex
            std::cout << "Invalid database file format. Creating new database..." << std::endl;
            file.close();
            return false;
        }

        // Read and verify version
        uint32_t version;
        file.read(reinterpret_cast<char*>(&version), sizeof(version));
        if (file.fail() || version != 1) {
            std::cout << "Invalid database version. Creating new database..." << std::endl;
            file.close();
            return false;
        }

        // Clear existing data
        users.clear();
        wallets.clear();
        transactions_.clear();

        // Read number of users
        size_t numUsers;
        file.read(reinterpret_cast<char*>(&numUsers), sizeof(numUsers));
        if (file.fail() || numUsers > 1000000) {  // Sanity check
            std::cout << "Invalid number of users in database. Creating new database..." << std::endl;
            file.close();
            return false;
        }

        std::cout << "Reading " << numUsers << " users..." << std::endl;
        // Read users
        for (size_t i = 0; i < numUsers; ++i) {
            User user = deserializeUser(file);
            if (file.fail()) {
                std::cout << "Error reading user data. Creating new database..." << std::endl;
                file.close();
                return false;
            }
            users[user.getUsername()] = std::make_shared<User>(user);
            std::cout << "Read user: " << user.getUsername() << std::endl;
        }

        // Read number of wallets
        size_t numWallets;
        file.read(reinterpret_cast<char*>(&numWallets), sizeof(numWallets));
        if (file.fail() || numWallets > 1000000) {  // Sanity check
            std::cout << "Invalid number of wallets in database. Creating new database..." << std::endl;
            file.close();
            return false;
        }

        std::cout << "Reading " << numWallets << " wallets..." << std::endl;
        // Read wallets
        for (size_t i = 0; i < numWallets; ++i) {
            Wallet wallet = deserializeWallet(file);
            if (file.fail()) {
                std::cout << "Error reading wallet data. Creating new database..." << std::endl;
                file.close();
                return false;
            }
            wallets[wallet.getId()] = std::make_shared<Wallet>(wallet);
            std::cout << "Read wallet: " << wallet.getId() << std::endl;
        }

        // Read transactions
        size_t numTransactions;
        file.read(reinterpret_cast<char*>(&numTransactions), sizeof(numTransactions));
        if (file.fail() || numTransactions > 1000000) {  // Sanity check
            std::cout << "Invalid number of transactions in database. Creating new database..." << std::endl;
            file.close();
            return false;
        }

        std::cout << "Reading " << numTransactions << " transactions..." << std::endl;
        for (size_t i = 0; i < numTransactions; ++i) {
            Transaction transaction = deserializeTransaction(file);
            if (file.fail()) {
                std::cout << "Error reading transaction data. Creating new database..." << std::endl;
                file.close();
                return false;
            }
            transactions_.push_back(transaction);
            std::cout << "Read transaction: " << transaction.id << std::endl;
        }

        // Verify checksum
        uint32_t storedChecksum;
        file.read(reinterpret_cast<char*>(&storedChecksum), sizeof(storedChecksum));
        if (file.fail()) {
            std::cout << "Error reading checksum. Creating new database..." << std::endl;
            file.close();
            return false;
        }

        file.close();
        lastFileModification = std::filesystem::last_write_time(DB_FILE);
        std::cout << "Database loaded successfully from: " << DB_FILE << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error loading database: " << e.what() << std::endl;
        return false;
    }
} 