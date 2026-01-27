#include <filesystem>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

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

// ==================== Pre-calculation Structures ====================

struct FileEntry {
    std::string fsPath;
    std::string internalPath;
    size_t size;
    bool isDirectory;
};

struct PreCalculatedBatch {
    std::vector<FileEntry> entries;
    size_t totalSize = 0;
    size_t fileCount = 0;
    size_t dirCount = 0;

    void clear() {
        entries.clear();
        totalSize = fileCount = dirCount = 0;
    }

    size_t getAllocationSize() const {
        return static_cast<size_t>(totalSize * 1.2) + (fileCount + dirCount) * 512;
    }
};

void scanAndCalculate(const std::string &fsPath, const std::string &basePath, PreCalculatedBatch &batch) {
    for (const auto &e: Filesystem::listDirectory(fsPath)) {
        std::string fullFsPath = Filesystem::joinPath(fsPath, e.name);
        std::string internalPath = basePath.empty() ? e.name : basePath + "/" + e.name;

        FileEntry fe{fullFsPath, internalPath, e.isDirectory ? 0 : Filesystem::getFileSize(fullFsPath), e.isDirectory};
        batch.entries.push_back(fe);

        if (e.isDirectory) {
            batch.dirCount++;
            scanAndCalculate(fullFsPath, internalPath, batch);
        } else {
            batch.fileCount++;
            batch.totalSize += fe.size;
        }
    }
}

PreCalculatedBatch calculateSingleFile(const std::string &fsPath, const std::string &internalPath) {
    PreCalculatedBatch batch;
    size_t sz = Filesystem::getFileSize(fsPath);
    batch.entries.push_back({fsPath, internalPath, sz, false});
    batch.fileCount = 1;
    batch.totalSize = sz;
    return batch;
}

PreCalculatedBatch calculateDirectory(const std::string &fsPath) {
    PreCalculatedBatch batch;
    scanAndCalculate(fsPath, "", batch);
    return batch;
}

// ==================== Utility Functions ====================

void clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

std::string getPassword(const std::string &prompt = "Password: ") {
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

std::string formatSize(size_t bytes) {
    const char *units[] = {"B", "KB", "MB", "GB"};
    int unit = 0;
    auto size = static_cast<double>(bytes);
    while (size >= 1024 && unit < 3) {
        size /= 1024;
        unit++;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(unit ? 2 : 0) << size << " " << units[unit];
    return oss.str();
}

class ProgressTracker {
    std::chrono::steady_clock::time_point start_ = std::chrono::steady_clock::now();
    int total_;
    std::string op_;

public:
    ProgressTracker(int t, const std::string &o) : total_(t), op_(o) {
    }

    void update(int cur) const {
        float p = total_ > 0 ? float(cur) / total_ : 0;
        int pos = int(40 * p);
        std::cout << "\r" << op_ << ": [" << (p < 0.3 ? "\033[91m" : p < 0.7 ? "\033[93m" : "\033[92m");
        for (int i = 0; i < 40; i++) std::cout << (i < pos ? "█" : i == pos ? "▶" : " ");
        std::cout << "\033[0m] " << std::fixed << std::setprecision(1) << p * 100 << "% (" << cur << "/" << total_ <<
                ")";
        if (cur > 0 && cur < total_) {
            auto el = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_).
                    count();
            if (el > 0) {
                int rem = int((total_ - cur) * el / cur);
                std::cout << " ETA:" << rem / 60 << ":" << std::setw(2) << std::setfill('0') << rem % 60 <<
                        std::setfill(' ');
            }
        }
        std::cout << "     ";
        std::cout.flush();
    }

    void finish() const {
        std::cout << "\r" << op_ <<
                ": [\033[92m████████████████████████████████████████\033[0m] 100% ✓                \n";
    }
};

std::vector<std::string> splitCommand(const std::string &cmd) {
    std::vector<std::string> tokens;
    std::string cur;
    bool dq = false, sq = false, esc = false;
    for (char c: cmd) {
        if (esc) {
            cur += c;
            esc = false;
            continue;
        }
        if (c == '\\') {
            esc = true;
            continue;
        }
        if (c == '"' && !sq) {
            dq = !dq;
            continue;
        }
        if (c == '\'' && !dq) {
            sq = !sq;
            continue;
        }
        if (c == ' ' && !dq && !sq) {
            if (!cur.empty()) {
                tokens.push_back(cur);
                cur.clear();
            }
        } else cur += c;
    }
    if (!cur.empty()) tokens.push_back(cur);
    return tokens;
}

void printHeader(const std::string &title) {
    clearScreen();
    std::cout << "╔════════════════════════════════════════╗\n║" << std::string((40 - title.length()) / 2, ' ') << title
            << std::string((41 - title.length()) / 2, ' ') << "║\n╚════════════════════════════════════════╝\n\n";
}

std::string normalizePath(const std::string &base, const std::string &path) {
    if (path.empty() || path == ".") return base;
    std::vector<std::string> parts;
    if (path[0] != '/' && base != "/" && !base.empty()) {
        std::istringstream iss(base);
        std::string seg;
        while (std::getline(iss, seg, '/')) if (!seg.empty()) parts.push_back(seg);
    }
    std::istringstream iss(path);
    std::string seg;
    while (std::getline(iss, seg, '/')) {
        if (seg.empty() || seg == ".") continue;
        if (seg == "..") { if (!parts.empty()) parts.pop_back(); } else parts.push_back(seg);
    }
    if (parts.empty()) return "/";
    std::string result;
    for (const auto &p: parts) result += "/" + p;
    return result;
}

std::string toInternalPath(const std::string &dp) {
    return (dp.empty() || dp == "/") ? "" : (dp[0] == '/' ? dp.substr(1) : dp);
}

// ==================== Line Editor ====================

class LineEditor {
    iNode *node_;
    std::string cwd_, line_;
    size_t cursor_ = 0;
    bool useFs_ = false;

    std::string getLastToken() const {
        auto p = line_.rfind(' ');
        return p == std::string::npos ? line_ : line_.substr(p + 1);
    }

    size_t getLastTokenStart() const {
        auto p = line_.rfind(' ');
        return p == std::string::npos ? 0 : p + 1;
    }

    static std::vector<std::string> getFsCompletions(const std::string &partial) {
        std::vector<std::string> c;
        std::string dir, pre;
        auto ls = partial.rfind('/'), bs = partial.rfind('\\');
        auto sep = (ls != std::string::npos && bs != std::string::npos)
                       ? std::max(ls, bs)
                       : (ls != std::string::npos ? ls : bs);
        if (sep == std::string::npos) {
            dir = ".";
            pre = partial;
        } else {
            dir = partial.substr(0, sep + 1);
            pre = partial.substr(sep + 1);
        }
        try {
            for (const auto &e: Filesystem::listDirectory(dir.empty() ? "." : dir))
                if (
                    pre.empty() || e.name.find(pre) == 0)
                    c.push_back(dir + e.name + (e.isDirectory ? "/" : ""));
        } catch (...) {
        }
        std::sort(c.begin(), c.end());
        return c;
    }

    std::vector<std::string> getLbCompletions(const std::string &partial) const {
        std::vector<std::string> c;
        if (!node_) return c;
        std::string dir, pre;
        auto ls = partial.rfind('/');
        if (ls == std::string::npos) {
            dir = toInternalPath(cwd_);
            pre = partial;
        } else {
            pre = partial.substr(ls + 1);
            dir = partial[0] == '/'
                      ? toInternalPath(partial.substr(0, ls))
                      : toInternalPath(normalizePath(cwd_, partial.substr(0, ls)));
        }
        for (const auto &e: node_->listDirectory(dir))
            if (pre.empty() || e.name.find(pre) == 0)
                c.push_back(
                    (ls != std::string::npos ? partial.substr(0, ls + 1) : "") + e.name + (e.isFile ? "" : "/"));
        std::sort(c.begin(), c.end());
        return c;
    }

    void redraw(const std::string &pr) const {
        std::cout << "\r\033[K" << pr << line_;
        if (cursor_ < line_.length()) std::cout << "\033[" << (line_.length() - cursor_) << "D";
        std::cout.flush();
    }

    void handleTab(const std::string &pr) {
        auto partial = getLastToken();
        auto comps = useFs_ ? getFsCompletions(partial) : getLbCompletions(partial);
        if (comps.empty()) return;
        auto ts = getLastTokenStart();
        if (comps.size() == 1) {
            auto cm = comps[0];
            if (cm.find(' ') != std::string::npos) cm = "\"" + cm + "\"";
            line_ = line_.substr(0, ts) + cm;
            cursor_ = line_.length();
            redraw(pr);
        } else {
            std::cout << "\n";
            for (const auto &x: comps) std::cout << "  " << x << "\n";
            std::string com = comps[0];
            for (size_t i = 1; i < comps.size(); i++) {
                size_t j = 0;
                while (j < com.length() && j < comps[i].length() && com[j] == comps[i][j]) j++;
                com = com.substr(0, j);
            }
            line_ = line_.substr(0, ts) + com;
            cursor_ = line_.length();
            std::cout << pr << line_;
            std::cout.flush();
        }
    }

public:
    LineEditor(iNode *n = nullptr, const std::string &c = "/") : node_(n), cwd_(c), useFs_(n == nullptr) {
    }

    void setNode(iNode *n) {
        node_ = n;
        useFs_ = !n;
    }

    void setCwd(const std::string &c) { cwd_ = c; }
    void setFilesystemMode(bool f) { useFs_ = f; }

    std::string readLine(const std::string &pr) {
        line_.clear();
        cursor_ = 0;
        std::cout << pr;
        std::cout.flush();
#ifdef _WIN32
        while (true) {
            int ch = _getch();
            if (ch == '\r' || ch == '\n') {
                std::cout << "\n";
                return line_;
            } else if (ch == '\t') handleTab(pr);
            else if (ch == '\b' || ch == 127) {
                if (cursor_ > 0) {
                    line_.erase(--cursor_, 1);
                    redraw(pr);
                }
            } else if (ch == 0 || ch == 224) {
                ch = _getch();
                if (ch == 75 && cursor_ > 0) {
                    cursor_--;
                    std::cout << "\033[D";
                } else if (ch == 77 && cursor_ < line_.length()) {
                    cursor_++;
                    std::cout << "\033[C";
                }
            } else if (ch >= 32) {
                line_.insert(cursor_++, 1, char(ch));
                redraw(pr);
            }
        }
#else
        termios o, n; tcgetattr(STDIN_FILENO, &o); n = o; n.c_lflag &= ~(ICANON | ECHO); n.c_cc[VMIN] = 1;
        n.c_cc[VTIME] = 0; tcsetattr(STDIN_FILENO, TCSANOW, &n);
        while (true) {
            char ch;
            read(STDIN_FILENO, &ch, 1);
            if (ch == '\n' || ch == '\r') {
                std::cout << "\n";
                tcsetattr(STDIN_FILENO, TCSANOW, &o);
                return line_;
            } else if (ch == '\t') handleTab(pr);
            else if (ch == 127 || ch == '\b') {
                if (cursor_ > 0) {
                    line_.erase(--cursor_, 1);
                    redraw(pr);
                }
            } else if (ch == 27) {
                char s[2];
                read(STDIN_FILENO, s, 2);
                if (s[0] == '[') {
                    if (s[1] == 'D' && cursor_ > 0) {
                        cursor_--;
                        std::cout << "\033[D";
                    } else if (s[1] == 'C' && cursor_ < line_.length()) {
                        cursor_++;
                        std::cout << "\033[C";
                    }
                    std::cout.flush();
                }
            } else if (ch >= 32) {
                line_.insert(cursor_++, 1, ch);
                redraw(pr);
            }
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &o);
#endif
    }
};

LineEditor g_fsEditor(nullptr);

std::string getPathWithCompletion(const std::string &pr) {
    g_fsEditor.setFilesystemMode(true);
    auto p = g_fsEditor.readLine(pr);
    if (!p.empty() && p.front() == '"') p.erase(0, 1);
    if (!p.empty() && p.back() == '"') p.pop_back();
    return p;
}

// ==================== Batch Insert ====================

bool insertBatchIntoLockbox(iNode *node, const PreCalculatedBatch &batch, bool showProg = true) {
    if (batch.entries.empty()) return true;
    size_t allocSz = batch.getAllocationSize();
    if (allocSz > 0) {
        if (showProg) std::cout << "🔧 Preallocazione " << formatSize(allocSz) << "...\n";
        node->preallocate(allocSz);
    }

    int proc = 0, tot = static_cast<int>(batch.entries.size());
    std::unique_ptr<ProgressTracker> prog;
    if (showProg) prog = std::make_unique<ProgressTracker>(tot, "🔐 Inserimento");

    for (const auto &e: batch.entries) {
        if (e.isDirectory) node->addDirectory(e.internalPath);
        else if (e.size > 0) {
            auto [sz, buf] = Filesystem::readFile(e.fsPath);
            std::cout << e.fsPath << std::endl;
            if (sz > 0 && !buf.empty())
                try {
                    node->addFile(e.internalPath, buf.data(), sz);
                } catch (const std::exception &ex) {
                    std::cerr << "\n❌ " << e.internalPath << ": " << ex.what() << "\n";
                }
        }
        if (prog) prog->update(++proc);
    }
    if (prog) prog->finish();
    return true;
}

// ==================== Menu Functions ====================

void showMainMenu();

void openLockbox();

void createLockbox();

void encryptText();

void decryptText();

void managementMenu(iNode *node);

void cliMode(iNode *node);

void showMainMenu() {
    while (true) {
        printHeader("LOCKBOX - Menu Principale");
        std::cout <<
                "  [1] Apri LockBox\n  [2] Crea LockBox\n  [3] Cifra testo\n  [4] Decifra testo\n  [0] Esci\n\n>> ";
        std::string ch;
        std::getline(std::cin, ch);
        if (ch == "1") openLockbox();
        else if (ch == "2") createLockbox();
        else if (ch == "3") encryptText();
        else if (ch == "4") decryptText();
        else if (ch == "0") {
            std::cout << "Arrivederci!\n";
            return;
        } else {
            std::cout << "Scelta non valida.\n";
            pressEnterToContinue();
        }
    }
}

void openLockbox() {
    printHeader("Apri LockBox");
    auto path = getPathWithCompletion("Path del LockBox: ");
    if (path.empty()) {
        std::cout << "Path non specificato.\n";
        pressEnterToContinue();
        return;
    }
    if (!Filesystem::exists(path)) {
        std::cout << "File non trovato.\n";
        pressEnterToContinue();
        return;
    }
    if (Filesystem::isDirectory(path)) {
        std::cout << "È una directory.\n";
        pressEnterToContinue();
        return;
    }
    auto pwd = getPassword();
    if (pwd.empty()) {
        std::cout << "Password vuota.\n";
        pressEnterToContinue();
        return;
    }
    auto *oes = new OES();
    oes->set_key(const_cast<char *>(pwd.c_str()));
    oes->extendWKey(OES_NUM_OF_BLOCKS);
    try {
        auto *node = new iNode(path, oes);
        std::cout << "Aperto!\n";
        pressEnterToContinue();
        managementMenu(node);
        delete node;
    } catch (const std::exception &e) {
        std::cout << "Errore: " << e.what() << "\n";
        pressEnterToContinue();
    }
    delete oes;
}

void createLockbox() {
    printHeader("Crea LockBox");
    auto src = getPathWithCompletion("Path sorgente: ");
    if (src.empty() || !Filesystem::exists(src)) {
        std::cout << "Sorgente non valida.\n";
        pressEnterToContinue();
        return;
    }
    auto dst = getPathWithCompletion("Path destinazione: ");
    if (dst.empty()) {
        std::cout << "Destinazione non valida.\n";
        pressEnterToContinue();
        return;
    }
    if (Filesystem::exists(dst)) {
        std::cout << "Sovrascrivere? (s/n): ";
        std::string c;
        std::getline(std::cin, c);
        if (c != "s" && c != "S") {
            std::cout << "Annullato.\n";
            pressEnterToContinue();
            return;
        }
    }
    auto pwd = getPassword();
    if (pwd.empty()) {
        std::cout << "Password vuota.\n";
        pressEnterToContinue();
        return;
    }
    if (pwd.length() < 8) {
        std::cout << "Password corta, continuare? (s/n): ";
        std::string c;
        std::getline(std::cin, c);
        if (c != "s" && c != "S") return;
    }
    auto pwd2 = getPassword("Conferma: ");
    if (pwd != pwd2) {
        std::cout << "Non coincidono.\n";
        pressEnterToContinue();
        return;
    }

    std::cout << "\n📊 Scansione...\n";
    PreCalculatedBatch batch = Filesystem::isDirectory(src)
                                   ? calculateDirectory(src)
                                   : calculateSingleFile(src, Filesystem::getFilename(src));
    std::cout << "📁 " << batch.dirCount << " dir | 📄 " << batch.fileCount << " file | 💾 " <<
            formatSize(batch.totalSize) << " | 🔧 " << formatSize(batch.getAllocationSize()) << "\n\n";

    auto *oes = new OES();
    oes->set_key(const_cast<char *>(pwd.c_str()));
    oes->extendWKey(OES_NUM_OF_BLOCKS);
    try {
        auto *node = new iNode(dst, oes);
        insertBatchIntoLockbox(node, batch, true);
        std::cout << "💾 Salvataggio...\n";
        node->save();
        std::cout << "\n✅ Creato!\n";
        pressEnterToContinue();
        managementMenu(node);
        delete node;
    } catch (const std::exception &e) {
        std::cout << "Errore: " << e.what() << "\n";
        pressEnterToContinue();
    }
    delete oes;
}

void encryptText() {
    printHeader("Cifra Testo");
    auto txt = getInput("Testo: ");
    if (txt.empty()) {
        std::cout << "Vuoto.\n";
        pressEnterToContinue();
        return;
    }
    auto pwd = getPassword();
    if (pwd.empty()) {
        std::cout << "Password vuota.\n";
        pressEnterToContinue();
        return;
    }
    auto iv = getInput("IV (opz): ");
    auto *oes = new OES();
    oes->set_key(const_cast<char *>(pwd.c_str()));
    oes->extendWKey(OES_NUM_OF_BLOCKS);
    if (!iv.empty()) {
        auto *b = MBLOCK::fromBytes(iv.c_str(), iv.length());
        if (b) {
            oes->setIV(b->getData(), b->getLen());
            delete b;
        }
    }
    try {
        oes->load_data_raw(const_cast<char *>(txt.c_str()), txt.length());
        oes->enc_adv();
        if (auto *cb = oes->get_cipherBlock(); cb && !cb->isNull()) {
            auto [d, s] = exportBlock(cb, OES_TYPE_HEX);
            if (auto h = static_cast<char *>(d)) {
                std::cout << "\n✅ " << h << "\n";
                free(h);
            }
        }
    } catch (const std::exception &e) { std::cout << "❌ " << e.what() << "\n"; }
    delete oes;
    pressEnterToContinue();
}

void decryptText() {
    printHeader("Decifra Testo");
    auto hex = getInput("Hex: ");
    auto pwd = getPassword();
    auto iv = getInput("IV (opz): ");
    auto *ib = importBlock(hex.c_str(), hex.length(), OES_TYPE_HEX);
    if (!ib) {
        std::cout << "Hex invalido.\n";
        pressEnterToContinue();
        return;
    }
    auto *oes = new OES();
    oes->set_key(const_cast<char *>(pwd.c_str()));
    oes->extendWKey(OES_NUM_OF_BLOCKS);
    if (!iv.empty()) {
        auto *b = MBLOCK::fromBytes(iv.c_str(), iv.length());
        if (b) {
            oes->setIV(b->getData(), b->getLen());
            delete b;
        }
    }
    oes->load_cipher_block(ib, true);
    oes->dec_adv();
    if (auto *pb = oes->get_plainBlock(); pb && !pb->isNull()) {
        auto r = pb->toBytes();
        std::cout << "\nDecifrato: ";
        std::cout.write(reinterpret_cast<char *>(r.first), r.second);
        std::cout << "\n";
        delete[] r.first;
    }
    delete oes;
    pressEnterToContinue();
}

void managementMenu(iNode *node) {
    while (true) {
        printHeader("Gestione LockBox");
        node->printStats();
        std::cout << "\n  [1] Estrai  [2] CLI  [3] Cerca  [4] Defrag  [5] Log  [6] Pulisci Log  [0] Salva/Esci\n\n>> ";
        std::string cmd;
        std::getline(std::cin, cmd);
        auto tk = splitCommand(cmd);
        if (tk.empty()) continue;
        if (tk[0] == "0") {
            node->save();
            std::cout << "Salvato!\n";
            pressEnterToContinue();
            return;
        } else if (tk[0] == "1") {
            auto pp = tk.size() > 1 ? tk[1] : "";
            auto dest = getPathWithCompletion("Destinazione: ");
            if (!Filesystem::exists(dest)) Filesystem::createDirectory(dest, true);
            try {
                node->exportTo(dest, pp);
                std::cout << "✅ Estratto in " << dest << "\n";
            } catch (const std::exception &e) { std::cout << "❌ " << e.what() << "\n"; }
            pressEnterToContinue();
        } else if (tk[0] == "2") cliMode(node);
        else if (tk[0] == "3") {
            if (tk.size() < 2) std::cout << "Specifica nome.\n";
            else {
                auto r = node->search(tk[1], false);
                if (r.empty()) std::cout << "Nessun risultato.\n";
                else for (const auto &p: r) std::cout << (node->exists(p, true) ? "📄 " : "📁 ") << p << "\n";
            }
            pressEnterToContinue();
        } else if (tk[0] == "4") {
            std::cout << (node->defragment() ? "Defrag OK.\n" : "Errore.\n");
            pressEnterToContinue();
        } else if (tk[0] == "5") {
            std::cout << "\n═══ LOG ═══\n" << node->getLog() << "════════════\n" << formatSize(node->getLogSize()) <<
                    "\n";
            pressEnterToContinue();
        } else if (tk[0] == "6") {
            std::cout << "Pulire? (s/n): ";
            std::string c;
            std::getline(std::cin, c);
            if (c == "s" || c == "S") {
                node->clearLog();
                std::cout << "OK.\n";
            }
            pressEnterToContinue();
        }
    }
}

void cliMode(iNode *node) {
    std::string cwd = "/";
    int maxIt = 10;
    LineEditor ed(node, cwd);
    auto toInt = [&](const std::string &p) { return toInternalPath(normalizePath(cwd, p)); };
    auto toDisp = [&](const std::string &p) { return normalizePath(cwd, p); };
    auto listDir = [&](const std::string &pp) {
        auto ent = node->listDirectory(pp);
        if (ent.empty()) {
            std::cout << "  (vuota)\n";
            return;
        }
        std::sort(ent.begin(), ent.end(), [](auto &a, auto &b) {
            return a.isFile != b.isFile ? !a.isFile : a.name < b.name;
        });
        int sh = 0;
        for (const auto &e: ent) {
            if (sh >= maxIt) {
                std::cout << "  ... altri " << ent.size() - maxIt << "\n";
                break;
            }
            std::cout << (e.isFile ? "  📄 " : "  📁 ") << e.name << (e.isFile ? " (" + formatSize(e.size) + ")" : "/")
                    << "\n";
            sh++;
        }
        std::cout << "Tot: " << ent.size() << "\n";
    };
    clearScreen();
    std::cout <<
            "╔════════════════════════════════════════╗\n║         LockBox CLI Mode               ║\n╚════════════════════════════════════════╝\n'help' per comandi.\n";
    while (true) {
        ed.setCwd(cwd);
        auto cl = ed.readLine("\033[1;32mlockbox\033[0m:\033[1;34m" + cwd + "\033[0m$ ");
        auto tk = splitCommand(cl);
        if (tk.empty()) continue;
        std::string cmd = tk[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
        if (cmd == "exit" || cmd == "quit") return;
        else if (cmd == "help")
            std::cout << "ls cd pwd cat rm mkdir mv cp rename find tree extract add limit clear info\n";
        else if (cmd == "clear" || cmd == "cls") clearScreen();
        else if (cmd == "pwd") std::cout << cwd << "\n";
        else if (cmd == "ls") {
            auto td = tk.size() > 1 ? toDisp(tk[1]) : cwd;
            auto tp = toInternalPath(td);
            if (!tp.empty() && !node->exists(tp, false)) {
                std::cout << "Non trovata.\n";
                continue;
            }
            std::cout << td << ":\n";
            listDir(tp);
        } else if (cmd == "cd") {
            if (tk.size() < 2 || tk[1] == "/") cwd = "/";
            else {
                auto nd = toDisp(tk[1]);
                auto np = toInternalPath(nd);
                if (nd != "/" && !np.empty() && !node->exists(np, false)) {
                    std::cout << "Non trovata.\n";
                    continue;
                }
                cwd = nd;
            }
        } else if (cmd == "cat") {
            if (tk.size() < 2) {
                std::cout << "Uso: cat <file>\n";
                continue;
            }
            auto tp = toInt(tk[1]);
            if (!node->exists(tp, true)) {
                std::cout << "Non trovato.\n";
                continue;
            }
            auto [d, s] = node->readFile(tp);
            if (d && s > 0) {
                std::cout.write(d, s);
                std::cout << "\n";
                delete[] d;
            }
        } else if (cmd == "rm") {
            if (tk.size() < 2) {
                std::cout << "Uso: rm <path>\n";
                continue;
            }
            auto tp = toInt(tk[1]);
            if (!node->exists(tp, true) && !node->exists(tp, false)) {
                std::cout << "Non trovato.\n";
                continue;
            }
            std::cout << "Eliminare? (s/n): ";
            std::string c;
            std::getline(std::cin, c);
            if (c == "s" || c == "S") std::cout << (node->remove(tp) ? "OK.\n" : "Errore.\n");
        } else if (cmd == "mkdir") {
            if (tk.size() < 2) {
                std::cout << "Uso: mkdir <path>\n";
                continue;
            }
            std::cout << (node->addDirectory(toInt(tk[1])) ? "Creata.\n" : "Errore.\n");
        } else if (cmd == "mv") {
            if (tk.size() < 3) {
                std::cout << "Uso: mv <src> <dst>\n";
                continue;
            }
            std::cout << (node->move(toInt(tk[1]), toInt(tk[2])) ? "OK.\n" : "Errore.\n");
        } else if (cmd == "cp") {
            if (tk.size() < 3) {
                std::cout << "Uso: cp <src> <dst>\n";
                continue;
            }
            std::cout << (node->copy(toInt(tk[1]), toInt(tk[2])) ? "OK.\n" : "Errore.\n");
        } else if (cmd == "rename") {
            if (tk.size() < 3) {
                std::cout << "Uso: rename <path> <nome>\n";
                continue;
            }
            std::cout << (node->rename(toInt(tk[1]), tk[2]) ? "OK.\n" : "Errore.\n");
        } else if (cmd == "find") {
            if (tk.size() < 2) {
                std::cout << "Uso: find <nome>\n";
                continue;
            }
            auto r = node->search(tk[1], false);
            if (r.empty()) std::cout << "Nessun risultato.\n";
            else for (const auto &x: r) std::cout << (node->exists(x, true) ? "📄 " : "📁 ") << x << "\n";
        } else if (cmd == "tree") {
            auto td = tk.size() > 1 ? toDisp(tk[1]) : cwd;
            auto tp = toInternalPath(td);
            if (!tp.empty() && !node->exists(tp, false)) {
                std::cout << "Non trovato.\n";
                continue;
            }
            std::cout << td << "\n";
            std::function<void(const std::string &, const std::string &)> pt = [&
                    ](const std::string &pp, const std::string &pf) {
                auto ent = node->listDirectory(pp);
                std::sort(ent.begin(), ent.end(), [](auto &a, auto &b) {
                    return a.isFile != b.isFile ? !a.isFile : a.name < b.name;
                });
                for (size_t i = 0; i < ent.size(); i++) {
                    bool last = i == ent.size() - 1;
                    std::cout << pf << (last ? "└── " : "├── ") << (ent[i].isFile ? "📄 " : "📁 ") << ent[i].name << (
                        ent[i].isFile ? "" : "/") << "\n";
                    if (!ent[i].isFile)
                        pt(pp.empty() ? ent[i].name : pp + "/" + ent[i].name,
                           pf + (last ? "    " : "│   "));
                }
            };
            pt(tp, "");
        } else if (cmd == "e" || cmd == "extract") {
            std::string pp, ep;
            if (tk.size() == 2) {
                pp = toInternalPath(cwd);
                ep = tk[1];
            } else if (tk.size() >= 3) {
                pp = toInt(tk[1]);
                ep = tk[2];
            } else {
                std::cout << "Uso: extract [path] <dst>\n";
                continue;
            }
            if (!Filesystem::exists(ep)) Filesystem::createDirectory(ep, true);
            try {
                node->exportTo(ep, pp);
                std::cout << "✅ " << ep << "\n";
            } catch (const std::exception &e) { std::cout << "❌ " << e.what() << "\n"; }
        } else if (cmd == "a" || cmd == "add") {
            if (tk.size() < 2) {
                std::cout << "Uso: add <file_ext> [path_int]\n";
                continue;
            }
            const auto &ext = tk[1];
            if (!Filesystem::exists(ext)) {
                std::cout << "Non trovato.\n";
                continue;
            }
            std::string fn = Filesystem::getFilename(ext), ip;
            if (tk.size() >= 3) {
                auto &ia = tk[2];
                if (!ia.empty() && ia.back() == '/') ip = toInt(ia + fn);
                else if (node->exists(toInt(ia), false)) ip = toInt(ia + "/" + fn);
                else ip = toInt(ia);
            } else ip = toInt(fn);
            // Pre-calcola e prealloca
            std::cout << "📊 Calcolo...\n";
            PreCalculatedBatch batch;
            if (Filesystem::isDirectory(ext)) batch = calculateDirectory(ext);
            else batch = calculateSingleFile(ext, ip);
            std::cout << "💾 " << formatSize(batch.totalSize) << " | 🔧 " << formatSize(batch.getAllocationSize()) <<
                    "\n";
            // Aggiorna path interni se era directory
            if (Filesystem::isDirectory(ext))
                for (auto &e: batch.entries)
                    e.internalPath = (ip.empty() ? "" : ip + "/") + e.internalPath;
            insertBatchIntoLockbox(node, batch, true);
        } else if (cmd == "limit") {
            if (tk.size() < 2) std::cout << "Limite: " << maxIt << "\n";
            else {
                try {
                    maxIt = std::max(1, std::stoi(tk[1]));
                    std::cout << "OK: " << maxIt << "\n";
                } catch (...) { std::cout << "Numero invalido.\n"; }
            }
        } else if (cmd == "info") {
            if (tk.size() < 2) {
                std::cout << "Uso: info <path>\n";
                continue;
            }
            auto td = toDisp(tk[1]);
            auto tp = toInternalPath(td);
            bool isF = node->exists(tp, true), isD = !isF && (td == "/" || tp.empty() || node->exists(tp, false));
            if (!isF && !isD) {
                std::cout << "Non trovato.\n";
                continue;
            }
            std::cout << "\n  Path: " << td << "\n  Tipo: " << (isF ? "📄 File" : "📁 Dir") << "\n";
        } else std::cout << "Comando sconosciuto.\n";
    }
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    showMainMenu();
    return 0;
}
