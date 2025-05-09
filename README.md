## Thành viên
1. Vũ Tất Thành - __K24DTCN638__
2. Nguyễn Quang Đạo - 
3. Nguyễn Việt - 
4. Nguyễn Viết Tùng - __K24DTCN633__

# E-Wallet Management System

A console-based e-wallet management system with user authentication, 2FA support, and point transfer capabilities.

## Features

1. User Management
   - Create user accounts with auto-generated passwords
   - Enable/disable 2FA authentication
   - Change passwords
   - Admin user with special privileges

2. Wallet Management
   - Create and manage wallets
   - Transfer points between wallets
   - View transaction history
   - View wallet balance

3. Security
   - Password hashing using SHA-256
   - Two-factor authentication using TOTP
   - Transaction rollback on failure
   - Secure data persistence

## Requirements

- C++17 compatible compiler
- CMake 3.31 or higher
- OpenSSL
- Boost (system and filesystem components)

## Building

1. Clone the repository:
```bash
git clone <repository-url>
cd ewallet-manager
```

2. Create a build directory and build the project:
```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## Usage

1. Run the executable:
```bash
./ewallet_manager
```

2. Default admin credentials:
   - Username: admin
   - Password: admin123

3. Follow the on-screen menu to:
   - Create new users
   - Manage wallets
   - Transfer points
   - View transaction history

## Data Storage

- User data and wallet information are stored in `database.dat`
- All data is automatically saved when the program exits
- Data is loaded when the program starts

## Security Notes

- Change the default admin password after first login
- Enable 2FA for additional security
- Keep your wallet ID secure
- Regularly check transaction history for unauthorized activities
