#include <iostream>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <functional>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <cctype>
#include <chrono>
#include <limits>
#include <thread>

#include "raw-layer.h"

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#endif

#include "OES.h"
#include "iNode.h"
#include "filesystem.h"
#include "OpenES/layer/interface.h"

namespace fs = std::filesystem;

// Forward declarations
void clearScreen();
std::string getPassword(const std::string &prompt = "Password: ");
std::string getInput(const std::string &prompt);
void pressEnterToContinue();
void showMainMenu();
void openLockbox();
void createLockbox();
void encryptText();
void decryptText();
void managementMenu(iNode *node, OES *oes);
void cliMode(iNode *node, OES *oes);

// ==================== Utility Functions ====================

void clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

std::string getPassword(const std::string &prompt) {
    std::cout << prompt;
    std::string password;
#ifdef _WIN32
    char ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b' && !password.empty()) {
            password.pop_back();
            std::cout << "\b \b";
        } else if (ch != '\b') {
            password += ch;
            std::cout << '*';
        }
    }
#else
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    std::cout << std::endl;
    return password;
}

std::string getInput(const std::string &prompt) {
    std::cout << prompt;
    std::string input;
    std::getline(std::cin, input);
    return input;
}

void pressEnterToContinue() {
    std::cout << "\nPremi INVIO per continuare...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void showProgress(int current, int total, const std::string& operation = "Operazione") {
    const int barWidth = 40;
    float progress = (total > 0) ? (float)current / total : 0.0f;
    int pos = barWidth * progress;
    
    std::cout << "\r" << operation << ": [";
    
    // Color coding based on progress
    if (progress < 0.3) std::cout << "\033[91m";  // Red
    else if (progress < 0.7) std::cout << "\033[93m"; // Yellow
    else std::cout << "\033[92m"; // Green
    
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) std::cout << "█";
        else if (i == pos) std::cout << "▶";
        else std::cout << " ";
    }
    
    std::cout << "\033[0m"; // Reset color
    std::cout << "] " << std::fixed << std::setprecision(1) << (progress * 100.0) << "% ";
    std::cout << "(" << current << "/" << total << ")";
    
    // Add ETA calculation if we have meaningful progress
    static auto startTime = std::chrono::steady_clock::now();
    if (current > 0 && current < total) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();
        if (elapsed > 0) {
            double rate = (double)current / elapsed;
            int remaining = (int)((total - current) / rate);
            if (remaining < 3600) {
                std::cout << " ETA: " << (remaining / 60) << ":" << (remaining % 60);
            } else {
                std::cout << " ETA: " << (remaining / 3600) << "h " << ((remaining % 3600) / 60) << "m";
            }
        }
    }
    std::cout.flush();
}

void finishProgress(const std::string& operation = "Operazione") {
    std::cout << "\r" << operation << ": [\033[92m████████████████████████████████████████\033[0m] 100.0% Completato!                     \n";
}

// Fixed splitCommand to handle paths with spaces in quotes
std::vector<std::string> splitCommand(const std::string &cmd) {
    std::vector<std::string> tokens;
    std::string current;
    bool inDoubleQuotes = false;
    bool inSingleQuotes = false;
    bool escaped = false;

    for (size_t i = 0; i < cmd.length(); i++) {
        char c = cmd[i];

        if (escaped) {
            current += c;
            escaped = false;
            continue;
        }

        if (c == '\\' && i + 1 < cmd.length()) {
            // Check if escaping a quote or space
            char next = cmd[i + 1];
            if (next == '"' || next == '\'' || next == ' ' || next == '\\') {
                escaped = true;
                continue;
            }
            current += c;
            continue;
        }

        if (c == '"' && !inSingleQuotes) {
            inDoubleQuotes = !inDoubleQuotes;
            continue;  // Don't add quote to token
        }

        if (c == '\'' && !inDoubleQuotes) {
            inSingleQuotes = !inSingleQuotes;
            continue;
        }

        if (c == ' ' && !inDoubleQuotes && !inSingleQuotes) {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
        } else {
            current += c;
        }
    }

    if (!current.empty()) {
        tokens.push_back(current);
    }

    return tokens;
}

void printHeader(const std::string &title) {
    clearScreen();
    std::cout << "╔════════════════════════════════════════╗\n";
    std::cout << "║" << std::string((40 - title.length()) / 2, ' ') << title
              << std::string((41 - title.length()) / 2, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════╝\n\n";
}

std::string normalizePath(const std::string &base, const std::string &path) {
    if (path.empty() || path == ".") return base;

    std::vector<std::string> parts;

    if (path[0] != '/' && base != "/" && !base.empty()) {
        std::istringstream iss(base);
        std::string seg;
        while (std::getline(iss, seg, '/'))
            if (!seg.empty()) parts.push_back(seg);
    }

    std::istringstream iss(path);
    std::string seg;
    while (std::getline(iss, seg, '/')) {
        if (seg.empty() || seg == ".") continue;
        if (seg == "..") { if (!parts.empty()) parts.pop_back(); }
        else parts.push_back(seg);
    }

    if (parts.empty()) return "/";
    std::string result;
    for (const auto &p : parts) result += "/" + p;
    return result;
}

std::string toInternalPath(const std::string &displayPath) {
    if (displayPath.empty() || displayPath == "/") return "";
    return (displayPath[0] == '/') ? displayPath.substr(1) : displayPath;
}

std::string formatSize(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024 && unit < 3) {
        size /= 1024;
        unit++;
    }
    std::ostringstream oss;
    if (unit == 0) oss << bytes << " " << units[unit];
    else oss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return oss.str();
}

// ==================== Line Editor with Tab Completion ====================

class LineEditor {
    iNode *node_;
    std::string cwd_;
    std::string line_;
    size_t cursor_ = 0;
    bool useFilesystem_ = false;  // true = external filesystem, false = lockbox

    std::string getLastToken() const {
        size_t lastSpace = line_.rfind(' ');
        if (lastSpace == std::string::npos) return line_;
        return line_.substr(lastSpace + 1);
    }

    size_t getLastTokenStart() const {
        size_t lastSpace = line_.rfind(' ');
        return (lastSpace == std::string::npos) ? 0 : lastSpace + 1;
    }

    std::vector<std::string> getFilesystemCompletions(const std::string &partial) {
        std::vector<std::string> completions;

        std::string dirPath, prefix;
        size_t lastSlash = partial.rfind('/');
        size_t lastBackslash = partial.rfind('\\');
        size_t lastSep = std::string::npos;

        if (lastSlash != std::string::npos && lastBackslash != std::string::npos)
            lastSep = std::max(lastSlash, lastBackslash);
        else if (lastSlash != std::string::npos)
            lastSep = lastSlash;
        else if (lastBackslash != std::string::npos)
            lastSep = lastBackslash;

        if (lastSep == std::string::npos) {
            dirPath = ".";
            prefix = partial;
        } else {
            dirPath = partial.substr(0, lastSep + 1);
            prefix = partial.substr(lastSep + 1);
        }

        try {
            auto entries = Filesystem::listDirectory(dirPath.empty() ? "." : dirPath);
            for (const auto &e : entries) {
                if (prefix.empty() || e.name.find(prefix) == 0) {
                    std::string completion = dirPath + e.name;
                    if (e.isDirectory) completion += "/";
                    completions.push_back(completion);
                }
            }
        } catch (...) {}

        std::sort(completions.begin(), completions.end());
        return completions;
    }

    std::vector<std::string> getLockboxCompletions(const std::string &partial) {
        std::vector<std::string> completions;
        if (!node_) return completions;

        std::string dirPath, prefix;
        size_t lastSlash = partial.rfind('/');

        if (lastSlash == std::string::npos) {
            dirPath = toInternalPath(cwd_);
            prefix = partial;
        } else {
            std::string partialDir = partial.substr(0, lastSlash);
            prefix = partial.substr(lastSlash + 1);

            if (partial[0] == '/') {
                dirPath = toInternalPath(partialDir.empty() ? "/" : partialDir);
            } else {
                std::string fullPath = normalizePath(cwd_, partialDir);
                dirPath = toInternalPath(fullPath);
            }
        }

        auto entries = node_->listDirectory(dirPath);

        for (const auto &e : entries) {
            if (prefix.empty() || e.name.find(prefix) == 0) {
                std::string completion = e.name;
                if (!e.isFile) completion += "/";

                if (lastSlash != std::string::npos) {
                    completion = partial.substr(0, lastSlash + 1) + completion;
                }
                completions.push_back(completion);
            }
        }

        std::sort(completions.begin(), completions.end());
        return completions;
    }

    void redrawLine(const std::string &prompt) {
        std::cout << "\r\033[K" << prompt << line_;
        if (cursor_ < line_.length()) {
            std::cout << "\033[" << (line_.length() - cursor_) << "D";
        }
        std::cout.flush();
    }

    void handleTab(const std::string &prompt) {
        std::string partial = getLastToken();
        auto completions = useFilesystem_ ? getFilesystemCompletions(partial)
                                          : getLockboxCompletions(partial);

        if (completions.empty()) return;

        size_t tokenStart = getLastTokenStart();

        if (completions.size() == 1) {
            // Single match - complete it
            std::string completion = completions[0];
            // If path has spaces, wrap in quotes
            if (completion.find(' ') != std::string::npos) {
                completion = "\"" + completion + "\"";
            }
            line_ = line_.substr(0, tokenStart) + completion;
            cursor_ = line_.length();
            redrawLine(prompt);
        } else {
            // Multiple matches - show them and complete common prefix
            std::cout << std::endl;
            for (const auto &c : completions) {
                std::cout << "  " << c << std::endl;
            }

            // Find common prefix
            std::string common = completions[0];
            for (size_t i = 1; i < completions.size(); i++) {
                size_t j = 0;
                while (j < common.length() && j < completions[i].length()
                       && common[j] == completions[i][j]) j++;
                common = common.substr(0, j);
            }

            line_ = line_.substr(0, tokenStart) + common;
            cursor_ = line_.length();
            std::cout << prompt << line_;
            std::cout.flush();
        }
    }

public:
    LineEditor(iNode *node = nullptr, const std::string &cwd = "/")
        : node_(node), cwd_(cwd), useFilesystem_(node == nullptr) {}

    void setNode(iNode *node) { node_ = node; useFilesystem_ = (node == nullptr); }
    void setCwd(const std::string &cwd) { cwd_ = cwd; }
    void setFilesystemMode(bool fs) { useFilesystem_ = fs; }

    std::string readLine(const std::string &prompt) {
        line_.clear();
        cursor_ = 0;

        std::cout << prompt;
        std::cout.flush();

#ifdef _WIN32
        while (true) {
            int ch = _getch();

            if (ch == '\r' || ch == '\n') {
                std::cout << std::endl;
                return line_;
            } else if (ch == '\t') {
                handleTab(prompt);
            } else if (ch == '\b' || ch == 127) {
                if (cursor_ > 0) {
                    line_.erase(cursor_ - 1, 1);
                    cursor_--;
                    redrawLine(prompt);
                }
            } else if (ch == 0 || ch == 224) {
                ch = _getch();
                if (ch == 75 && cursor_ > 0) { cursor_--; std::cout << "\033[D"; }
                else if (ch == 77 && cursor_ < line_.length()) { cursor_++; std::cout << "\033[C"; }
            } else if (ch >= 32) {
                line_.insert(cursor_, 1, (char)ch);
                cursor_++;
                redrawLine(prompt);
            }
        }
#else
        termios oldt, newt;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        newt.c_cc[VMIN] = 1;
        newt.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);

        while (true) {
            char ch;
            read(STDIN_FILENO, &ch, 1);

            if (ch == '\n' || ch == '\r') {
                std::cout << std::endl;
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
                return line_;
            } else if (ch == '\t') {
                handleTab(prompt);
            } else if (ch == 127 || ch == '\b') {
                if (cursor_ > 0) {
                    line_.erase(cursor_ - 1, 1);
                    cursor_--;
                    redrawLine(prompt);
                }
            } else if (ch == 27) {
                char seq[2];
                read(STDIN_FILENO, &seq[0], 1);
                read(STDIN_FILENO, &seq[1], 1);
                if (seq[0] == '[') {
                    if (seq[1] == 'D' && cursor_ > 0) { cursor_--; std::cout << "\033[D"; std::cout.flush(); }
                    else if (seq[1] == 'C' && cursor_ < line_.length()) { cursor_++; std::cout << "\033[C"; std::cout.flush(); }
                }
            } else if (ch >= 32) {
                line_.insert(cursor_, 1, ch);
                cursor_++;
                redrawLine(prompt);
            }
        }

        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
        return line_;
    }
};

// Global line editor for filesystem paths
LineEditor g_fsEditor(nullptr);

std::string getPathWithCompletion(const std::string &prompt) {
    g_fsEditor.setFilesystemMode(true);
    std::string path = g_fsEditor.readLine(prompt);
    
    // Remove quotes if present
    if (!path.empty() && path.front() == '"') path.erase(0, 1);
    if (!path.empty() && path.back() == '"') path.pop_back();
    
    return path;
}

// ==================== Main Menu ====================

void showMainMenu() {
    while (true) {
        printHeader("LOCKBOX - Menu Principale");
        std::cout << "  [1] Apri LockBox\n";
        std::cout << "  [2] Crea LockBox\n";
        std::cout << "  [3] Cifra testo\n";
        std::cout << "  [4] Decifra testo\n";
        std::cout << "  [0] Esci\n";
        std::cout << "\n>> ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") openLockbox();
        else if (choice == "2") createLockbox();
        else if (choice == "3") encryptText();
        else if (choice == "4") decryptText();
        else if (choice == "0") { std::cout << "Arrivederci!\n"; return; }
        else { std::cout << "Scelta non valida.\n"; pressEnterToContinue(); }
    }
}

// ==================== Open Lockbox ====================

void openLockbox() {
    printHeader("Apri LockBox");

    std::string path = getPathWithCompletion("Path del LockBox (TAB per completare): ");
    
    // Enhanced path validation
    if (path.empty()) {
        std::cout << "Errore: Path non specificato.\n";
        pressEnterToContinue();
        return;
    }
    
    try {
        if (!fs::exists(path)) {
            std::cout << "Errore: File o directory non trovata: " << path << "\n";
            pressEnterToContinue();
            return;
        }
        
        if (fs::is_directory(path)) {
            std::cout << "Errore: Il path specificato è una directory, non un file LockBox.\n";
            pressEnterToContinue();
            return;
        }
        
        // Check if file is readable
        std::ifstream testFile(path);
        if (!testFile.is_open()) {
            std::cout << "Errore: Impossibile leggere il file. Verifica i permessi.\n";
            pressEnterToContinue();
            return;
        }
        testFile.close();
        
    } catch (const fs::filesystem_error& e) {
        std::cout << "Errore nel path: " << e.what() << "\n";
        pressEnterToContinue();
        return;
    } catch (const std::exception& e) {
        std::cout << "Errore durante la verifica del file: " << e.what() << "\n";
        pressEnterToContinue();
        return;
    }

    std::string password = getPassword("Password: ");
    if (password.empty()) {
        std::cout << "Errore: Password vuota.\n";
        pressEnterToContinue();
        return;
    }

    auto oes = new OES();
    oes->set_key(const_cast<char*>(password.c_str()));
    oes->extendWKey(OES_NUM_OF_BLOCKS);

    try {
        iNode *node = new iNode(path, oes);
        std::cout << "LockBox aperto con successo!\n";
        pressEnterToContinue();
        managementMenu(node, oes);
        delete node;
    } catch (const std::exception &e) {
        std::cout << "Errore apertura LockBox: " << e.what() << "\n";
        pressEnterToContinue();
    }
    delete oes;
}

// ==================== Create Lockbox ====================

void createLockbox() {
    printHeader("Crea LockBox");

    std::cout << "Inserisci il path della cartella/file da cifrare\n";
    std::cout << "(usa TAB per completamento automatico):\n";
    std::string sourcePath = getPathWithCompletion(">> ");

    // Enhanced source path validation
    if (sourcePath.empty()) {
        std::cout << "Errore: Path sorgente non specificato.\n";
        pressEnterToContinue();
        return;
    }

    try {
        if (!Filesystem::exists(sourcePath)) {
            std::cout << "Errore: Path sorgente non trovato: " << sourcePath << "\n";
            pressEnterToContinue();
            return;
        }

        // Check if source is readable by attempting to open it
        std::ifstream testSource(sourcePath);
        if (!testSource.is_open() && !Filesystem::isDirectory(sourcePath)) {
            std::cout << "Errore: Impossibile leggere il file sorgente. Verifica i permessi.\n";
            pressEnterToContinue();
            return;
        }
        testSource.close();

    } catch (const std::exception& e) {
        std::cout << "Errore durante la verifica del path sorgente: " << e.what() << "\n";
        pressEnterToContinue();
        return;
    }

std::string destPath = getPathWithCompletion("Path di destinazione del LockBox: ");
    
    // Validate destination path
    if (destPath.empty()) {
        std::cout << "Errore: Path di destinazione non specificato.\n";
        pressEnterToContinue();
        return;
    }

    // Check if destination already exists
    if (Filesystem::exists(destPath)) {
        std::cout << "Attenzione: Il file di destinazione esiste già. Sovrascrivere? (s/n): ";
        std::string overwrite;
        std::getline(std::cin, overwrite);
        if (overwrite != "s" && overwrite != "S") {
            std::cout << "Operazione annullata.\n";
            pressEnterToContinue();
            return;
        }
    }

    std::string password = getPassword("Password: ");
    if (password.empty()) {
        std::cout << "Errore: Password non può essere vuota.\n";
        pressEnterToContinue();
        return;
    }
    
    if (password.length() < 8) {
        std::cout << "Attenzione: La password è corta (meno di 8 caratteri). Continuare? (s/n): ";
        std::string continuePwd;
        std::getline(std::cin, continuePwd);
        if (continuePwd != "s" && continuePwd != "S") {
            std::cout << "Operazione annullata.\n";
            pressEnterToContinue();
            return;
        }
    }
    
    std::string confirmPwd = getPassword("Conferma password: ");

    if (password != confirmPwd) {
        std::cout << "Errore: Le password non coincidono.\n";
        pressEnterToContinue();
        return;
    }

    auto oes = new OES();
    oes->set_key(const_cast<char*>(password.c_str()));
    oes->extendWKey(OES_NUM_OF_BLOCKS);

try {
        iNode *node = new iNode(destPath, oes);
        
        // Count total files for progress tracking
        int totalFiles = 0;
        int totalDirs = 0;
        std::function<void(const fs::path&)> countItems;
        countItems = [&](const fs::path &p) {
            for (const auto &entry : fs::directory_iterator(p)) {
                if (entry.is_directory()) {
                    totalDirs++;
                    countItems(entry.path());
                } else if (entry.is_regular_file()) {
                    totalFiles++;
                }
            }
        };
        
        if (fs::is_directory(sourcePath)) {
            countItems(sourcePath);
        } else {
            totalFiles = 1;
        }
        
        std::cout << "\n📦 Creazione LockBox in corso...\n";
        std::cout << "📁 Cartelle: " << totalDirs << " | 📄 File: " << totalFiles << "\n\n";
        
        int processedFiles = 0;
        int processedDirs = 0;
        int totalItems = totalFiles + totalDirs;

        std::function<void(const fs::path&, const std::string&)> addRecursive;
        addRecursive = [&](const fs::path &p, const std::string &basePath) {
            for (const auto &entry : fs::directory_iterator(p)) {
                std::string relPath = basePath.empty()
                    ? entry.path().filename().string()
                    : basePath + "/" + entry.path().filename().string();

                if (entry.is_directory()) {
                    node->addDirectory(relPath);
                    processedDirs++;
                    showProgress(processedDirs + processedFiles, totalItems, "📁 Creazione directory");
                    addRecursive(entry.path(), relPath);
                } else if (entry.is_regular_file()) {
                    size_t fileSize = entry.file_size();
                    if (fileSize == 0) {
                        processedFiles++;
                        showProgress(processedDirs + processedFiles, totalItems, "⏭️  Elaborazione file");
                        continue;
                    }
                    std::ifstream file(entry.path(), std::ios::binary);
                    if (!file.is_open()) {
                        std::cout << "\n❌ Errore apertura file: " << relPath << "\n";
                        processedFiles++;
                        showProgress(processedDirs + processedFiles, totalItems, "⚠️  Errore file");
                        continue;
                    }
                    std::vector<char> buffer(fileSize);
                    file.read(buffer.data(), fileSize);
                    file.close();
                    try {
                        node->addFile(relPath, buffer.data(), fileSize);
                        processedFiles++;
                        showProgress(processedDirs + processedFiles, totalItems, "🔐 Cifratura file");
                    } catch (const std::exception &e) {
                        std::cout << "\n❌ Errore cifratura: " << relPath << " - " << e.what() << "\n";
                        processedFiles++;
                        showProgress(processedDirs + processedFiles, totalItems, "❌ Errore cifratura");
                    }
                }
            }
        };

if (fs::is_directory(sourcePath)) {
            addRecursive(sourcePath, "");
        } else {
            std::cout << "📄 Elaborazione singolo file...\n";
            std::ifstream file(sourcePath, std::ios::binary | std::ios::ate);
            size_t size = file.tellg();
            file.seekg(0);
            std::vector<char> buffer(size);
            file.read(buffer.data(), size);
            file.close();
            std::string filename = fs::path(sourcePath).filename().string();
            
            showProgress(0, 1, "🔐 Cifratura file");
            node->addFile(filename, buffer.data(), size);
            showProgress(1, 1, "✅ File cifrato");
        }

        std::cout << "\n💾 Salvataggio LockBox in corso...\n";
        showProgress(0, 1, "💾 Salvataggio");
        node->save();
        finishProgress("💾 LockBox creato");
        
        std::cout << "\n✅ LockBox creato con successo!\n";
        std::cout << "📊 Statistiche: " << totalFiles << " file e " << totalDirs << " cartelle processati\n";
        pressEnterToContinue();
        managementMenu(node, oes);
        delete node;
    } catch (const std::exception &e) {
        std::cout << "Errore creazione LockBox: " << e.what() << "\n";
        pressEnterToContinue();
    }
    delete oes;
}

// ==================== Encrypt/Decrypt Text ====================

void encryptText() {
    printHeader("Cifra Testo (ADV)");
    std::string text = getInput("Testo da cifrare: ");
    
    if (text.empty()) {
        std::cout << "Errore: Il testo da cifrare non può essere vuoto.\n";
        pressEnterToContinue();
        return;
    }
    
    std::string password = getPassword("Password: ");
    if (password.empty()) {
        std::cout << "Errore: La password non può essere vuota.\n";
        pressEnterToContinue();
        return;
    }
    
    std::string ivStr = getInput("IV (opzionale, premi INVIO per default): ");

    auto oes = new OES();
    oes->set_key(const_cast<char*>(password.c_str()));
    oes->extendWKey(OES_NUM_OF_BLOCKS);

    if (!ivStr.empty()) {
        auto *ivBlock = MBLOCK::fromBytes(ivStr.c_str(), ivStr.length());
        if (!ivBlock) {
            std::cout << "Errore: IV non valido. Utilizzo IV di default.\n";
        } else {
            oes->setIV(ivBlock->getData(), ivBlock->getLen());
            delete ivBlock;
        }
    }

    try {
        oes->load_data_raw(const_cast<char*>(text.c_str()), text.length());
        oes->enc_adv();

        auto *cipherBlock = oes->get_cipherBlock();
        if (cipherBlock && !cipherBlock->isNull()) {
            auto exported = exportBlock(cipherBlock, OES_TYPE_HEX);
            char *hexStr = static_cast<char*>(exported.first);
            if (hexStr) {
                std::cout << "\n✅ Testo cifrato con successo (hex): " << hexStr << "\n";
                std::cout << "📏 Lunghezza: " << strlen(hexStr) << " caratteri\n";
                free(hexStr);
            } else {
                std::cout << "❌ Errore durante l'esportazione del testo cifrato.\n";
            }
        } else {
            std::cout << "❌ Errore durante la cifratura del testo.\n";
        }
    } catch (const std::exception& e) {
        std::cout << "❌ Errore durante la cifratura: " << e.what() << "\n";
    }
    
    delete oes;
    pressEnterToContinue();
}

void decryptText() {
    printHeader("Decifra Testo (ADV)");
    std::string hexText = getInput("Testo cifrato (hex): ");
    std::string password = getPassword("Password: ");
    std::string ivStr = getInput("IV (opzionale, premi INVIO per default): ");

    MBLOCK *inputBlock = importBlock(hexText.c_str(), hexText.length(), OES_TYPE_HEX);
    if (!inputBlock) {
        std::cout << "Errore: input hex non valido.\n";
        pressEnterToContinue();
        return;
    }

    auto oes = new OES();
    oes->set_key(const_cast<char*>(password.c_str()));
    oes->extendWKey(OES_NUM_OF_BLOCKS);

    if (!ivStr.empty()) {
        auto *ivBlock = MBLOCK::fromBytes(ivStr.c_str(), ivStr.length());
        oes->setIV(ivBlock->getData(), ivBlock->getLen());
        delete ivBlock;
    }

    oes->load_cipher_block(inputBlock, true);
    oes->dec_adv();

    auto *plainBlock = oes->get_plainBlock();
    if (plainBlock && !plainBlock->isNull()) {
        auto result = plainBlock->toBytes();
        std::cout << "\nTesto decifrato: ";
        std::cout.write(reinterpret_cast<char*>(result.first), result.second);
        std::cout << "\n";
        delete[] result.first;
    } else {
        std::cout << "Errore durante la decifratura.\n";
    }
    delete oes;
    pressEnterToContinue();
}

// ==================== Management Menu ====================

void managementMenu(iNode *node, OES *oes) {
    while (true) {
        printHeader("Gestione LockBox");
        node->printStats();

        std::cout << "\nComandi disponibili:\n";
        std::cout << "  [1] [path]      - Estrai (tutto o path specifico)\n";
        std::cout << "  [2]             - Modalita CLI\n";
        std::cout << "  [3] <nome>      - Cerca file/cartella\n";
        std::cout << "  [4]             - Deframmenta\n";
        std::cout << "  [5]             - Visualizza Log\n";
        std::cout << "  [6]             - Pulisci Log\n";
        std::cout << "  [0]             - Salva ed esci\n";
        std::cout << "\n>> ";

        std::string cmd;
        std::getline(std::cin, cmd);
        auto tokens = splitCommand(cmd);
        if (tokens.empty()) continue;

        if (tokens[0] == "0") {
            node->save();
            std::cout << "Salvato!\n";
            pressEnterToContinue();
            return;
} else if (tokens[0] == "1") {
            std::string plainPath = tokens.size() > 1 ? tokens[1] : "";
            std::string destDir = getPathWithCompletion("Directory di destinazione: ");
            if (!Filesystem::exists(destDir)) {
                std::cout << "📁 Creazione directory destinazione...\n";
                fs::create_directories(destDir);
            }
            
            try {
                // Count files to export for progress tracking
                auto exportItems = node->listDirectory(plainPath);
                int totalExportItems = exportItems.size();
                
                if (totalExportItems == 0) {
                    std::cout << "⚠️ Nessun file da esportare nel path specificato.\n";
                    pressEnterToContinue();
                    continue;
                }
                
                std::cout << "📦 Esportazione in corso...\n";
                std::cout << "📄 File da esportare: " << totalExportItems << "\n\n";
                
                int exportedCount = 0;
                auto originalExportTo = [&](const std::string& dest, const std::string& path) {
                    // This would normally be node->exportTo(dest, path)
                    // For now, we'll simulate progress
                    for (int i = 0; i <= totalExportItems; i++) {
                        showProgress(i, totalExportItems, "📤 Estrazione file");
                        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Simulate work
                    }
                };
                
                node->exportTo(destDir, plainPath);
                finishProgress("📤 Estrazione completata");
                
                std::cout << "\n✅ Estratto con successo in: " << destDir << "\n";
                std::cout << "📊 File esportati: " << totalExportItems << "\n";
            } catch (const std::exception &e) {
                std::cout << "\n❌ Errore durante l'esportazione: " << e.what() << "\n";
            }
            pressEnterToContinue();
        } else if (tokens[0] == "2") {
            cliMode(node, oes);
        } else if (tokens[0] == "3") {
            if (tokens.size() < 2) {
                std::cout << "Specifica un nome da cercare.\n";
            } else {
                auto results = node->search(tokens[1], false);
                if (results.empty()) {
                    std::cout << "Nessun risultato trovato.\n";
                } else {
                    std::cout << "Trovati " << results.size() << " risultati:\n";
                    for (const auto &p : results) {
                        bool isFile = node->exists(p, true);
                        std::cout << (isFile ? "  📄 " : "  📁 ") << p << "\n";
                    }
                }
            }
            pressEnterToContinue();
        } else if (tokens[0] == "4") {
            std::cout << "Deframmentazione in corso...\n";
            if (node->defragment()) std::cout << "Deframmentazione completata.\n";
            else std::cout << "Errore durante la deframmentazione.\n";
            pressEnterToContinue();
        } else if (tokens[0] == "5") {
            std::cout << "\n═══════════════ LOG OPERAZIONI ═══════════════\n";
            std::cout << node->getLog();
            std::cout << "══════════════════════════════════════════════\n";
            std::cout << "Dimensione log: " << formatSize(node->getLogSize()) << "\n";
            pressEnterToContinue();
        } else if (tokens[0] == "6") {
            std::cout << "Pulire il log? (s/n): ";
            std::string confirm;
            std::getline(std::cin, confirm);
            if (confirm == "s" || confirm == "S") {
                node->clearLog();
                std::cout << "Log pulito.\n";
            }
            pressEnterToContinue();
        } else {
            std::cout << "Comando non riconosciuto.\n";
            pressEnterToContinue();
        }
    }
}

// ==================== CLI Mode ====================

void cliMode(iNode *node, OES *oes) {
    std::string cwd = "/";
    int maxItems = 10;
    std::vector<std::string> commandHistory;
    int historyIndex = -1;
    LineEditor editor(node, cwd);

    auto resolveToInternal = [&](const std::string &userPath) -> std::string {
        std::string full = normalizePath(cwd, userPath);
        return toInternalPath(full);
    };

    auto resolveToDisplay = [&](const std::string &userPath) -> std::string {
        return normalizePath(cwd, userPath);
    };

    auto showHelp = []() {
        std::cout << "\nComandi disponibili:\n";
        std::cout << "  ls [path]              - Elenca contenuto directory\n";
        std::cout << "  cd <path>              - Cambia directory\n";
        std::cout << "  pwd                    - Mostra directory corrente\n";
        std::cout << "  cat <file>             - Mostra contenuto file (testo)\n";
        std::cout << "  info <path>            - Mostra info dettagliate\n";
        std::cout << "  tree [path]            - Mostra struttura ad albero\n";
        std::cout << "  find <nome>            - Cerca file/cartella\n";
        std::cout << "  mv <src> <dest>        - Sposta file/cartella\n";
        std::cout << "  cp <src> <dest>        - Copia file/cartella\n";
        std::cout << "  rm <path>              - Elimina file/cartella\n";
        std::cout << "  mkdir <path>           - Crea directory\n";
        std::cout << "  rename <path> <nome>   - Rinomina file/cartella\n";
        std::cout << "  e|extract [path] <dst> - Estrai nel filesystem\n";
        std::cout << "  a|add <ext> [int]      - Importa file esterno\n";
        std::cout << "  limit <n>              - Imposta max elementi (ls)\n";
        std::cout << "  clear|cls              - Pulisce schermo\n";
        std::cout << "  help                   - Mostra questo aiuto\n";
        std::cout << "  exit|quit              - Torna al menu principale\n";
        std::cout << "\n  Usa TAB per autocompletare i path!\n";
    };

    auto listDir = [&](const std::string &plainPath) {
        auto entries = node->listDirectory(plainPath);
        if (entries.empty()) {
            std::cout << "  (directory vuota)\n";
            return;
        }

        std::sort(entries.begin(), entries.end(), [](const auto &a, const auto &b) {
            if (a.isFile != b.isFile) return !a.isFile;
            return a.name < b.name;
        });

        int shown = 0;
        for (const auto &e : entries) {
            if (shown >= maxItems) {
                std::cout << "  ... e altri " << (entries.size() - maxItems) << " elementi\n";
                break;
            }
            if (e.isFile) std::cout << "  📄 " << e.name << " (" << formatSize(e.size) << ")\n";
            else std::cout << "  📁 " << e.name << "/\n";
            shown++;
        }
        std::cout << "\nTotale: " << entries.size() << " elementi\n";
    };

    clearScreen();
    std::cout << "╔════════════════════════════════════════╗\n";
    std::cout << "║         LockBox CLI Mode               ║\n";
    std::cout << "╚════════════════════════════════════════╝\n";
    std::cout << "Digita 'help' per la lista dei comandi.\n";
    std::cout << "Usa TAB per autocompletare i path!\n\n";

    while (true) {
        std::string prompt = "\033[1;32mlockbox\033[0m:\033[1;34m" + cwd + "\033[0m$ ";
        editor.setCwd(cwd);
        std::string cmdLine = editor.readLine(prompt);

        auto tokens = splitCommand(cmdLine);
        if (tokens.empty()) continue;

        std::string cmd = tokens[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

        if (cmd == "exit" || cmd == "quit") {
            return;
        }
        else if (cmd == "help") {
            showHelp();
        }
        else if (cmd == "clear" || cmd == "cls") {
            clearScreen();
        }
        else if (cmd == "pwd") {
            std::cout << cwd << "\n";
        }
        else if (cmd == "ls") {
            std::string targetDisplay = (tokens.size() > 1) ? resolveToDisplay(tokens[1]) : cwd;
            std::string targetPlain = toInternalPath(targetDisplay);

            if (!targetPlain.empty() && !node->exists(targetPlain, false)) {
                std::cout << "Directory non trovata: " << tokens[1] << "\n";
                continue;
            }

            std::cout << "Contenuto di " << targetDisplay << ":\n";
            listDir(targetPlain);
        }
        else if (cmd == "cd") {
            if (tokens.size() < 2 || tokens[1] == "/") {
                cwd = "/";
            } else {
                std::string newDisplay = resolveToDisplay(tokens[1]);
                std::string newPlain = toInternalPath(newDisplay);

                if (newDisplay != "/" && !newPlain.empty() && !node->exists(newPlain, false)) {
                    std::cout << "Directory non trovata: " << tokens[1] << "\n";
                    continue;
                }
                cwd = newDisplay;
            }
        }
        else if (cmd == "info") {
            if (tokens.size() < 2) {
                std::cout << "Uso: info <path>\n";
            } else {
                std::string targetDisplay = resolveToDisplay(tokens[1]);
                std::string targetPlain = toInternalPath(targetDisplay);

                // Get block info directly
                node->clearCache();
                node->syncRoot();

                bool isFile = node->exists(targetPlain, true);
                bool isDir = !isFile && (targetDisplay == "/" || targetPlain.empty() || node->exists(targetPlain, false));

                if (!isFile && !isDir) {
                    std::cout << "Path non trovato: " << tokens[1] << "\n";
                    continue;
                }

                std::cout << "\n╔══════════════════════════════════════════════════════╗\n";
                std::cout << "║                    INFORMAZIONI                       ║\n";
                std::cout << "╠══════════════════════════════════════════════════════╣\n";
                std::cout << "  Path:           " << targetDisplay << "\n";
                std::cout << "  Tipo:           " << (isFile ? "📄 File" : "📁 Directory") << "\n";

                // Get detailed block info via walk
                node->walk(targetPlain.empty() ? "/" : targetPlain, [&](Block *b, const std::string &p, iNode *) {
                    if (toInternalPath(normalizePath("/", p)) == targetPlain ||
                        (targetPlain.empty() && p == "/")) {
                        std::cout << "  iNode pos:      " << b->current << "\n";
                        std::cout << "  Parent pos:     " << b->parent << "\n";
                        std::cout << "  Livello:        " << b->level << "\n";

                        if (b->isFile) {
                            std::cout << "  Dimensione:     " << formatSize(b->size) << " (" << b->size << " bytes)\n";
                            std::cout << "  Data pos:       " << b->data_pos << "\n";
                        } else {
                            std::cout << "  Sottocartelle:  " << b->folders_n << "\n";
                            std::cout << "  File:           " << b->files_n << "\n";
                            std::cout << "  Subdir pos:     " << b->subdir_pos << "\n";
                            std::cout << "  Data pos:       " << b->data_pos << "\n";
                        }

                        std::cout << "  Creato:         " << b->getCreatedAtStr() << "\n";
                        std::cout << "  Modificato:     " << b->getModifiedAtStr() << "\n";
                        std::cout << "  Accesso:        " << b->getAccessedAtStr() << "\n";
                        std::cout << "  Precedente:     " << b->previous << "\n";
                        std::cout << "  Successivo:     " << b->next << "\n";
                    }
                });

                std::cout << "╚══════════════════════════════════════════════════════╝\n";
            }
        }
        else if (cmd == "rm") {
            if (tokens.size() < 2) {
                std::cout << "Uso: rm <path>\n";
            } else {
                // Force cache clear and sync before checking
                node->clearCache();
                node->syncRoot();

                std::string targetPlain = resolveToInternal(tokens[1]);
                std::string targetDisplay = resolveToDisplay(tokens[1]);

                bool isFile = node->exists(targetPlain, true);
                bool isDir = node->exists(targetPlain, false);

                if (!isFile && !isDir) {
                    std::cout << "Path non trovato: " << tokens[1] << "\n";
                    continue;
                }

                std::cout << "Eliminare '" << targetDisplay << "'? (s/n): ";
                std::string confirm;
                std::getline(std::cin, confirm);
                if (confirm == "s" || confirm == "S") {
                    // Clear cache before and after removal
                    node->clearCache();
                    bool success = node->remove(targetPlain);
                    node->clearCache();
                    node->syncRoot();

                    if (success) {
                        std::cout << "Eliminato.\n";
                    } else {
                        std::cout << "Errore eliminazione.\n";
                    }
                }
            }
        }
        else if (cmd == "tree") {
            std::string targetDisplay = (tokens.size() > 1) ? resolveToDisplay(tokens[1]) : cwd;
            std::string targetPlain = toInternalPath(targetDisplay);

            if (!targetPlain.empty() && !node->exists(targetPlain, false)) {
                std::cout << "Path non trovato: " << tokens[1] << "\n";
                continue;
            }

            std::cout << targetDisplay << "\n";

            std::function<void(const std::string&, const std::string&)> printTree;
            printTree = [&](const std::string &plainPath, const std::string &prefix) {
                auto entries = node->listDirectory(plainPath);
                std::sort(entries.begin(), entries.end(), [](const auto &a, const auto &b) {
                    if (a.isFile != b.isFile) return !a.isFile;
                    return a.name < b.name;
                });

                for (size_t i = 0; i < entries.size(); i++) {
                    const auto &e = entries[i];
                    bool isLast = (i == entries.size() - 1);
                    std::string conn = isLast ? "└── " : "├── ";
                    std::string childPfx = prefix + (isLast ? "    " : "│   ");

                    if (e.isFile) {
                        std::cout << prefix << conn << "📄 " << e.name << "\n";
                    } else {
                        std::cout << prefix << conn << "📁 " << e.name << "/\n";
                        std::string childPlain = plainPath.empty() ? e.name : plainPath + "/" + e.name;
                        printTree(childPlain, childPfx);
                    }
                }
            };
            printTree(targetPlain, "");
        }
        else if (cmd == "find") {
            if (tokens.size() < 2) {
                std::cout << "Uso: find <nome>\n";
            } else {
                auto results = node->search(tokens[1], false);
                if (results.empty()) {
                    std::cout << "Nessun risultato.\n";
                } else {
                    std::cout << "Trovati " << results.size() << " risultati:\n";
                    for (const auto &r : results) {
                        bool isF = node->exists(r, true);
                        std::cout << (isF ? "  📄 " : "  📁 ") << r << "\n";
                    }
                }
            }
        }
        else if (cmd == "mv") {
            if (tokens.size() < 3) {
                std::cout << "Uso: mv <sorgente> <destinazione>\n";
            } else {
                std::string srcPlain = resolveToInternal(tokens[1]);
                std::string destPlain = resolveToInternal(tokens[2]);

                if (!node->exists(srcPlain, true) && !node->exists(srcPlain, false)) {
                    std::cout << "Sorgente non trovata: " << tokens[1] << "\n";
                    continue;
                }

                if (node->move(srcPlain, destPlain))
                    std::cout << "Spostato con successo.\n";
                else
                    std::cout << "Errore spostamento.\n";
            }
        }
        else if (cmd == "cp") {
            if (tokens.size() < 3) {
                std::cout << "Uso: cp <sorgente> <destinazione>\n";
            } else {
                std::string srcPlain = resolveToInternal(tokens[1]);
                std::string destPlain = resolveToInternal(tokens[2]);

                if (!node->exists(srcPlain, true) && !node->exists(srcPlain, false)) {
                    std::cout << "Sorgente non trovata: " << tokens[1] << "\n";
                    continue;
                }

                if (node->copy(srcPlain, destPlain))
                    std::cout << "Copiato con successo.\n";
                else
                    std::cout << "Errore copia.\n";
            }
        }
        else if (cmd == "mkdir") {
            if (tokens.size() < 2) {
                std::cout << "Uso: mkdir <path>\n";
            } else {
                std::string newDirInternal = resolveToInternal(tokens[1]);
                std::string newDirDisplay = resolveToDisplay(tokens[1]);

                if (node->addDirectory(newDirInternal))
                    std::cout << "Directory creata: " << newDirDisplay << "\n";
                else
                    std::cout << "Errore creazione directory.\n";
            }
        }
        else if (cmd == "rename") {
            if (tokens.size() < 3) {
                std::cout << "Uso: rename <path> <nuovo_nome>\n";
            } else {
                std::string targetPlain = resolveToInternal(tokens[1]);

                if (!node->exists(targetPlain, true) && !node->exists(targetPlain, false)) {
                    std::cout << "Path non trovato: " << tokens[1] << "\n";
                    continue;
                }

                if (node->rename(targetPlain, tokens[2]))
                    std::cout << "Rinominato in: " << tokens[2] << "\n";
                else
                    std::cout << "Errore rinomina.\n";
            }
        }
else if (cmd == "e" || cmd == "extract") {
            std::string plainPath, extPath;

            if (tokens.size() == 2) {
                plainPath = toInternalPath(cwd);
                extPath = tokens[1];
            } else if (tokens.size() >= 3) {
                plainPath = resolveToInternal(tokens[1]);
                extPath = tokens[2];
            } else {
                std::cout << "Uso: extract [path_interno] <path_esterno>\n";
                continue;
            }

            if (!Filesystem::exists(extPath)) {
                std::cout << "📁 Creazione directory destinazione...\n";
                fs::create_directories(extPath);
            }
            
            try {
                // Count items to extract for progress
                auto extractItems = node->listDirectory(plainPath);
                int totalExtractItems = extractItems.size();
                
                if (totalExtractItems == 0) {
                    std::cout << "⚠️ Nessun file da estrarre nel path specificato.\n";
                    continue;
                }
                
                std::cout << "📤 Estrazione in corso...\n";
                std::cout << "📁 File da estrarre: " << totalExtractItems << "\n\n";
                
                node->exportTo(extPath, plainPath);
                finishProgress("📤 Estrazione completata");
                
                std::cout << "✅ Estratto con successo in: " << extPath << "\n";
                std::cout << "📊 File estratti: " << totalExtractItems << "\n";
            } catch (const std::exception &e) {
                std::cout << "\n❌ Errore durante l'estrazione: " << e.what() << "\n";
            }
        }
        else if (cmd == "a" || cmd == "add") {
            if (tokens.size() < 2) {
                std::cout << "Uso: add <file_esterno> [path_interno]\n";
            } else {
                const std::string& extPath = tokens[1];
                std::string plainPath;
                std::string extFilename = fs::path(extPath).filename().string();

                if (tokens.size() >= 3) {
                    const std::string& internalArg = tokens[2];

                    if (!internalArg.empty() && internalArg.back() == '/') {
                        plainPath = resolveToInternal(internalArg + extFilename);
                    }
                    else if (node->exists(resolveToInternal(internalArg), false)) {
                        plainPath = resolveToInternal(internalArg + "/" + extFilename);
                    }
                    else {
                        plainPath = resolveToInternal(internalArg);
                    }
                } else {
                    plainPath = resolveToInternal(extFilename);
                }

                if (!fs::exists(extPath)) {
                    std::cout << "File esterno non trovato: " << extPath << "\n";
                    continue;
                }

                if (size_t result = node->importFile(plainPath, extPath); result > 0)
                    std::cout << "Importato: " << extPath << " -> " << plainPath << "\n";
                else
                    std::cout << "Errore importazione.\n";
            }
        }
        else if (cmd == "cat") {
            if (tokens.size() < 2) {
                std::cout << "Uso: cat <file>\n";
            } else {
                std::string targetPlain = resolveToInternal(tokens[1]);

                if (!node->exists(targetPlain, true)) {
                    std::cout << "File non trovato: " << tokens[1] << "\n";
                    continue;
                }

                auto [data, size] = node->readFile(targetPlain);
                if (data && size > 0) {
                    std::cout.write(data, size);
                    std::cout << "\n";
                    delete[] data;
                } else {
                    std::cout << "(file vuoto o errore lettura)\n";
                }
            }
        }
        else if (cmd == "limit") {
            if (tokens.size() < 2) {
                std::cout << "Limite attuale: " << maxItems << " elementi\n";
            } else {
                try {
                    maxItems = std::stoi(tokens[1]);
                    if (maxItems < 1) maxItems = 10;
                    std::cout << "Limite impostato a " << maxItems << " elementi.\n";
                } catch (...) {
                    std::cout << "Numero non valido.\n";
                }
            }
        }
        else {
            std::cout << "Comando non riconosciuto. Digita 'help' per aiuto.\n";
        }
    }
}

// ==================== Main Entry Point ====================

int main(int argc, char *argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

  showMainMenu();

    return 0;
}