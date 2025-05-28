#include "ui.hpp"
#include <iostream>
#include <string>
#include <filesystem>

#include "database.hpp"

// TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [--db-path <path>]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --db-path <path>    Base path for database files (default: current directory)" << std::endl;
}

int main(int argc, char* argv[]) {
    try {
        std::filesystem::path dbPath;
        
        // Parse command line arguments
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            std::cout << "Processing argument: " << arg << std::endl;
            
            if (arg == "--db-path") {
                if (i + 1 < argc) {
                    dbPath = argv[++i];
                    std::cout << "Database path specified: " << dbPath << std::endl;
                    
                    // Convert to absolute path if it's not already
                    if (!dbPath.is_absolute()) {
                        dbPath = std::filesystem::absolute(dbPath);
                        std::cout << "Converted to absolute path: " << dbPath << std::endl;
                    }
                    
                    if (!std::filesystem::exists(dbPath)) {
                        std::cerr << "Error: Database path does not exist: " << dbPath << std::endl;
                        return 1;
                    }
                    
                    // Check if it's a directory
                    if (!std::filesystem::is_directory(dbPath)) {
                        std::cerr << "Error: Database path is not a directory: " << dbPath << std::endl;
                        return 1;
                    }
                    
                    std::cout << "Database path is valid and accessible" << std::endl;
                } else {
                    std::cerr << "Error: --db-path requires a path argument" << std::endl;
                    printUsage(argv[0]);
                    return 1;
                }
            } else if (arg == "--help" || arg == "-h") {
                printUsage(argv[0]);
                return 0;
            } else {
                std::cerr << "Error: Unknown argument: " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        }

        // Initialize database with the specified path
        if (!dbPath.empty()) {
            std::cout << "Setting database base path to: " << dbPath << std::endl;
            Database::getInstance().setBasePath(dbPath);
        } else {
            std::cout << "No database path specified, using current directory" << std::endl;
        }

        UI::getInstance().start();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown error occurred." << std::endl;
        return 1;
    }
    return 0;
    // TIP See CLion help at <a href="https://www.jetbrains.com/help/clion/">jetbrains.com/help/clion/</a>. Also, you can try interactive lessons for CLion by selecting 'Help | Learn IDE Features' from the main menu.
}