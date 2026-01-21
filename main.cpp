#include <iostream>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <functional>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include "OES.h"
#include "iNode.h"
#include "utility.h"
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
    std::cin.get();
}

std::vector<std::string> splitCommand(const std::string &cmd) {
    std::vector<std::string> tokens;
    bool inQuotes = false;
    std::string current;
    for (char c : cmd) {
        if (c == '"') inQuotes = !inQuotes;
        else if (c == ' ' && !inQuotes) {
            if (!current.empty()) { tokens.push_back(current); current.clear(); }
        } else current += c;
    }
    if (!current.empty()) tokens.push_back(current);
    return tokens;
}

void printHeader(const std::string &title) {
    clearScreen();
    std::cout << "╔════════════════════════════════════════╗\n";
    std::cout << "║" << std::string((40 - title.length()) / 2, ' ') << title
              << std::string((41 - title.length()) / 2, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════╝\n\n";
}

// Normalize path (handles . and ..) - works with PLAIN paths
std::string normalizePath(const std::string &base, const std::string &path) {
    if (path.empty() || path == ".") return base;
    
    std::vector<std::string> parts;
    
    // If absolute path, start fresh; otherwise start with base
    if (path[0] != '/' && base != "/" && !base.empty()) {
        std::istringstream iss(base);
        std::string seg;
        while (std::getline(iss, seg, '/'))
            if (!seg.empty()) parts.push_back(seg);
    }
    
    // Process the path
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

// Convert display path "/a/b" to internal path "a/b" (remove leading slash)
std::string toInternalPath(const std::string &displayPath) {
    if (displayPath.empty() || displayPath == "/") return "";
    return (displayPath[0] == '/') ? displayPath.substr(1) : displayPath;
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

    std::string path = getInput("Path del LockBox: ");
    if (path.empty() || !fs::exists(path)) {
        std::cout << "Errore: File non trovato.\n";
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
    std::cout << "(puoi trascinare qui la cartella):\n";
    std::string sourcePath = getInput(">> ");

    if (!sourcePath.empty() && sourcePath.front() == '"') sourcePath.erase(0, 1);
    if (!sourcePath.empty() && sourcePath.back() == '"') sourcePath.pop_back();

    if (!fs::exists(sourcePath)) {
        std::cout << "Errore: Path non valido.\n";
        pressEnterToContinue();
        return;
    }

    std::string destPath = getInput("Path di destinazione del LockBox: ");
    std::string password = getPassword("Password: ");
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
        std::cout << "\nCifratura in corso...\n";

        std::function<void(const fs::path&, const std::string&)> addRecursive;
        addRecursive = [&](const fs::path &p, const std::string &basePath) {
            for (const auto &entry : fs::directory_iterator(p)) {
                std::string relPath = basePath.empty()
                    ? entry.path().filename().string()
                    : basePath + "/" + entry.path().filename().string();

                if (entry.is_directory()) {
                    node->addDirectory(relPath);
                    std::cout << "  [DIR]  " << relPath << "\n";
                    addRecursive(entry.path(), relPath);
                } else if (entry.is_regular_file()) {
                    size_t fileSize = entry.file_size();
                    if (fileSize == 0) {
                        std::cout << "  [SKIP] " << relPath << " (file vuoto)\n";
                        continue;
                    }
                    std::ifstream file(entry.path(), std::ios::binary);
                    if (!file.is_open()) {
                        std::cout << "  [ERR]  " << relPath << " (impossibile aprire)\n";
                        continue;
                    }
                    std::vector<char> buffer(fileSize);
                    file.read(buffer.data(), fileSize);
                    file.close();
                    try {
                        node->addFile(relPath, buffer.data(), fileSize);
                        std::cout << "  [FILE] " << relPath << " (" << fileSize << " bytes)\n";
                    } catch (const std::exception &e) {
                        std::cout << "  [ERR]  " << relPath << " (" << e.what() << ")\n";
                    }
                }
            }
        };

        if (fs::is_directory(sourcePath)) {
            addRecursive(sourcePath, "");
        } else {
            std::ifstream file(sourcePath, std::ios::binary | std::ios::ate);
            size_t size = file.tellg();
            file.seekg(0);
            std::vector<char> buffer(size);
            file.read(buffer.data(), size);
            file.close();
            std::string filename = fs::path(sourcePath).filename().string();
            node->addFile(filename, buffer.data(), size);
            std::cout << "  [FILE] " << filename << " (" << size << " bytes)\n";
        }

        node->save();
        std::cout << "\nLockBox creato con successo!\n";
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
    std::string password = getPassword("Password: ");
    std::string ivStr = getInput("IV (opzionale, premi INVIO per default): ");

    auto oes = new OES();
    oes->set_key(const_cast<char*>(password.c_str()));
    oes->extendWKey(OES_NUM_OF_BLOCKS);

    if (!ivStr.empty()) {
        auto *ivBlock = MBLOCK::fromBytes(ivStr.c_str(), ivStr.length());
        oes->setIV(ivBlock->getData(), ivBlock->getLen());
        delete ivBlock;
    }

    oes->load_data_raw(const_cast<char*>(text.c_str()), text.length());
    oes->enc_adv();

    auto *cipherBlock = oes->get_cipherBlock();
    if (cipherBlock && !cipherBlock->isNull()) {
        auto exported = exportBlock(cipherBlock, OES_TYPE_HEX);
        char *hexStr = static_cast<char*>(exported.first);
        if (hexStr) {
            std::cout << "\nTesto cifrato (hex): " << hexStr << "\n";
            free(hexStr);
        }
    } else {
        std::cout << "Errore durante la cifratura.\n";
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
            std::string destDir = getInput("Directory di destinazione: ");
            if (!fs::exists(destDir)) fs::create_directories(destDir);
            try {
                // API now accepts plain paths directly
                node->exportTo(destDir, plainPath);
                std::cout << "Estratto in: " << destDir << "\n";
            } catch (const std::exception &e) {
                std::cout << "Errore: " << e.what() << "\n";
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
        } else {
            std::cout << "Comando non riconosciuto.\n";
            pressEnterToContinue();
        }
    }
}

// ==================== CLI Mode (Shell Simulation) ====================
// Now uses PLAIN paths everywhere - iNode handles encryption internally

void cliMode(iNode *node, OES *oes) {
    std::string cwd = "/";  // Current working directory (PLAIN path)
    int maxItems = 10;

    // Helper: resolve user path relative to cwd, returns internal format (no leading /)
    auto resolveToInternal = [&](const std::string &userPath) -> std::string {
        std::string full = normalizePath(cwd, userPath);
        return toInternalPath(full);
    };

    // Helper: resolve user path to display format (with leading /)
    auto resolveToDisplay = [&](const std::string &userPath) -> std::string {
        return normalizePath(cwd, userPath);
    };

    auto showHelp = []() {
        std::cout << "\nComandi disponibili:\n";
        std::cout << "  ls [path]              - Elenca contenuto directory\n";
        std::cout << "  cd <path>              - Cambia directory\n";
        std::cout << "  pwd                    - Mostra directory corrente\n";
        std::cout << "  cat <file>             - Mostra contenuto file (testo)\n";
        std::cout << "  info <path>            - Mostra info file/cartella\n";
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
        std::cout << "  exit|quit              - Torna al menu principale\n\n";
    };

    auto listDir = [&](const std::string &plainPath) {
        // listDirectory accepts plain paths (with or without leading /)
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
            // e.name is already decrypted by listDirectory
            if (e.isFile) std::cout << "  📄 " << e.name << " (" << e.size << " bytes)\n";
            else std::cout << "  📁 " << e.name << "/\n";
            shown++;
        }
        std::cout << "\nTotale: " << entries.size() << " elementi\n";
    };

    clearScreen();
    std::cout << "╔════════════════════════════════════════╗\n";
    std::cout << "║         LockBox CLI Mode               ║\n";
    std::cout << "╚════════════════════════════════════════╝\n";
    std::cout << "Digita 'help' per la lista dei comandi.\n\n";

    while (true) {
        std::cout << "\033[1;32mlockbox\033[0m:\033[1;34m" << cwd << "\033[0m$ ";
        std::string cmdLine;
        std::getline(std::cin, cmdLine);

        auto tokens = splitCommand(cmdLine);
        if (tokens.empty()) continue;

        std::string cmd = tokens[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

        // ===== EXIT =====
        if (cmd == "exit" || cmd == "quit") {
            return;
        }
        // ===== HELP =====
        else if (cmd == "help") {
            showHelp();
        }
        // ===== CLEAR =====
        else if (cmd == "clear" || cmd == "cls") {
            clearScreen();
        }
        // ===== PWD =====
        else if (cmd == "pwd") {
            std::cout << cwd << "\n";
        }
        // ===== LS =====
        else if (cmd == "ls") {
            std::string targetDisplay = (tokens.size() > 1) ? resolveToDisplay(tokens[1]) : cwd;
            std::string targetPlain = toInternalPath(targetDisplay);

            // Check if directory exists (empty string = root, always exists)
            if (!targetPlain.empty() && !node->exists(targetPlain, false)) {
                std::cout << "Directory non trovata: " << tokens[1] << "\n";
                continue;
            }

            std::cout << "Contenuto di " << targetDisplay << ":\n";
            listDir(targetPlain);
        }
        // ===== CD =====
        else if (cmd == "cd") {
            if (tokens.size() < 2 || tokens[1] == "/") {
                cwd = "/";
            } else {
                std::string newDisplay = resolveToDisplay(tokens[1]);
                std::string newPlain = toInternalPath(newDisplay);

                // Root is always valid
                if (newDisplay != "/" && !newPlain.empty() && !node->exists(newPlain, false)) {
                    std::cout << "Directory non trovata: " << tokens[1] << "\n";
                    continue;
                }
                cwd = newDisplay;
            }
        }
        // ===== TREE =====
        else if (cmd == "tree") {
            std::string targetDisplay = (tokens.size() > 1) ? resolveToDisplay(tokens[1]) : cwd;
            std::string targetPlain = toInternalPath(targetDisplay);

            if (!targetPlain.empty() && !node->exists(targetPlain, false)) {
                std::cout << "Path non trovato: " << tokens[1] << "\n";
                continue;
            }

            std::cout << targetDisplay << "\n";

            // Recursive tree using plain paths
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
                        // Build child plain path
                        std::string childPlain = plainPath.empty() ? e.name : plainPath + "/" + e.name;
                        printTree(childPlain, childPfx);
                    }
                }
            };
            printTree(targetPlain, "");
        }
        // ===== FIND =====
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
                        bool isFile = node->exists(r, true);
                        std::cout << (isFile ? "  📄 " : "  📁 ") << r << "\n";
                    }
                }
            }
        }
        // ===== MV =====
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
        // ===== CP =====
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
        // ===== RM =====
        else if (cmd == "rm") {
            if (tokens.size() < 2) {
                std::cout << "Uso: rm <path>\n";
            } else {
                std::string targetPlain = resolveToInternal(tokens[1]);
                std::string targetDisplay = resolveToDisplay(tokens[1]);

                if (!node->exists(targetPlain, true) && !node->exists(targetPlain, false)) {
                    std::cout << "Path non trovato: " << tokens[1] << "\n";
                    continue;
                }

                std::cout << "Eliminare '" << targetDisplay << "'? (s/n): ";
                std::string confirm;
                std::getline(std::cin, confirm);
                if (confirm == "s" || confirm == "S") {
                    if (node->remove(targetPlain))
                        std::cout << "Eliminato.\n";
                    else
                        std::cout << "Errore eliminazione.\n";
                }
            }
        }
        // ===== MKDIR =====
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
        // ===== RENAME =====
        else if (cmd == "rename") {
            if (tokens.size() < 3) {
                std::cout << "Uso: rename <path> <nuovo_nome>\n";
            } else {
                std::string targetPlain = resolveToInternal(tokens[1]);

                if (!node->exists(targetPlain, true) && !node->exists(targetPlain, false)) {
                    std::cout << "Path non trovato: " << tokens[1] << "\n";
                    continue;
                }

                // tokens[2] is the new plain name
                if (node->rename(targetPlain, tokens[2]))
                    std::cout << "Rinominato in: " << tokens[2] << "\n";
                else
                    std::cout << "Errore rinomina.\n";
            }
        }
        // ===== EXTRACT =====
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

            if (!fs::exists(extPath)) fs::create_directories(extPath);
            try {
                node->exportTo(extPath, plainPath);
                std::cout << "Estratto in: " << extPath << "\n";
            } catch (const std::exception &e) {
                std::cout << "Errore: " << e.what() << "\n";
            }
        }
        // ===== ADD =====
        else if (cmd == "a" || cmd == "add") {
            if (tokens.size() < 2) {
                std::cout << "Uso: add <file_esterno> [path_interno]\n";
            } else {
                std::string extPath = tokens[1];
                std::string plainPath;

                if (tokens.size() >= 3) {
                    plainPath = resolveToInternal(tokens[2]);
                } else {
                    std::string filename = fs::path(extPath).filename().string();
                    plainPath = resolveToInternal(filename);
                }

                if (!fs::exists(extPath)) {
                    std::cout << "File esterno non trovato: " << extPath << "\n";
                    continue;
                }

                size_t result = node->importFile(plainPath, extPath);
                if (result > 0)
                    std::cout << "Importato: " << extPath << "\n";
                else
                    std::cout << "Errore importazione.\n";
            }
        }
        // ===== INFO =====
        else if (cmd == "info") {
            if (tokens.size() < 2) {
                std::cout << "Uso: info <path>\n";
            } else {
                std::string targetDisplay = resolveToDisplay(tokens[1]);
                std::string targetPlain = toInternalPath(targetDisplay);

                bool isFile = node->exists(targetPlain, true);
                bool isDir = node->exists(targetPlain, false);

                // Root is always a directory
                if (targetDisplay == "/" || targetPlain.empty()) isDir = true;

                if (!isFile && !isDir) {
                    std::cout << "Path non trovato: " << tokens[1] << "\n";
                } else {
                    std::cout << "Path: " << targetDisplay << "\n";
                    std::cout << "Tipo: " << (isFile ? "File" : "Directory") << "\n";
                    if (isDir) {
                        std::cout << "Sottocartelle: " << node->countSubdirs(targetPlain) << "\n";
                        std::cout << "File: " << node->countFiles(targetPlain) << "\n";
                    }
                }
            }
        }
        // ===== CAT =====
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
        // ===== LIMIT =====
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
        // ===== DEBUG =====
        else if (cmd == "debug") {
            std::cout << "=== Debug Info ===\n";
            std::cout << "Cipher engine: " << (node->getCipherEngine() ? "ATTIVO" : "NULL") << "\n";
            std::cout << "CWD: " << cwd << "\n";
            
            // Test decryption on first entry
            auto entries = node->listDirectory("");
            if (!entries.empty()) {
                const auto &e = entries[0];
                std::cout << "First entry encrypted: " << e.encryptedName << "\n";
                std::cout << "First entry decrypted: " << e.name << "\n";
                std::cout << "Same? " << (e.encryptedName == e.name ? "YES (decrypt failed)" : "NO (decrypt worked)") << "\n";
            }
        } else {
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