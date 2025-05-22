#pragma once

#include "user.hpp"
#include "wallet.hpp"
#include <memory>

class UI {
public:
    static UI& getInstance();

    void start();
    void showMainMenu();
    void showUserMenu(std::shared_ptr<User> user);
    void showAdminMenu(std::shared_ptr<User> admin);
    void showWalletMenu(std::shared_ptr<User> user);
    void toggle2FA(std::shared_ptr<User> user);

private:
    UI();
    ~UI();

    // Prevent copying
    UI(const UI&) = delete;
    UI& operator=(const UI&) = delete;

    // Authentication
    std::shared_ptr<User> login();
    bool authenticateUser(const std::string& username, const std::string& password);
    bool verify2FA(std::shared_ptr<User> user);

    // User management
    void createUser();
    void updateUser(std::shared_ptr<User> user);
    void deleteUser();
    void listUsers();
    void changePassword(std::shared_ptr<User> user);

    // Wallet management
    void createWallet(std::shared_ptr<User> user);
    void transferPoints(std::shared_ptr<User> user);
    void viewBalance(std::shared_ptr<User> user);
    void viewTransactionHistory(std::shared_ptr<User> user);

    // Helper functions
    void clearScreen();
    void waitForEnter();
    std::string getInput(const std::string& prompt);
    double getAmountInput(const std::string& prompt);
    std::chrono::system_clock::time_point getDateInput(const std::string& prompt);

    void registerUser();
}; 