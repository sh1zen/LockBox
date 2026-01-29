#include <filesystem>
#include <iostream>
#include <deque>
#include <utility>

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

// ==================== Color Support ====================

class ColorSupport {
    bool enabled_ = true;

public:
    ColorSupport() {
#ifdef _WIN32
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode;
        enabled_ = GetConsoleMode(h, &mode) &&
                   SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#else
        const char *term = getenv("TERM");
        const char *colorterm = getenv("COLORTERM");
        enabled_ = isatty(STDOUT_FILENO) &&
                   (colorterm || (term && strstr(term, "color")));
#endif
    }

    [[nodiscard]] std::string red(const std::string &s) const { return enabled_ ? "\033[91m" + s + "\033[0m" : s; }
    [[nodiscard]] std::string green(const std::string &s) const { return enabled_ ? "\033[92m" + s + "\033[0m" : s; }
    [[nodiscard]] std::string yellow(const std::string &s) const { return enabled_ ? "\033[93m" + s + "\033[0m" : s; }
    [[nodiscard]] std::string blue(const std::string &s) const { return enabled_ ? "\033[94m" + s + "\033[0m" : s; }
    [[nodiscard]] std::string cyan(const std::string &s) const { return enabled_ ? "\033[96m" + s + "\033[0m" : s; }
    [[nodiscard]] std::string bold(const std::string &s) const { return enabled_ ? "\033[1m" + s + "\033[0m" : s; }

    [[nodiscard]] std::string boldGreen(const std::string &s) const {
        return enabled_ ? "\033[1;32m" + s + "\033[0m" : s;
    }

    [[nodiscard]] std::string boldBlue(const std::string &s) const {
        return enabled_ ? "\033[1;34m" + s + "\033[0m" : s;
    }

    [[nodiscard]] std::string dim(const std::string &s) const { return enabled_ ? "\033[2m" + s + "\033[0m" : s; }

    [[nodiscard]] std::string progressBar(float p) const {
        if (!enabled_) {
            const int pos = static_cast<int>(40 * p);
            std::string bar(pos, '#');
            bar += std::string(40 - pos, ' ');
            return "[" + bar + "]";
        }
        const std::string col = p < 0.3 ? "\033[91m" : p < 0.7 ? "\033[93m" : "\033[92m";
        const int pos = static_cast<int>(40 * p);
        std::string bar;
        for (int i = 0; i < 40; i++) bar += (i < pos ? "█" : i == pos ? "▶" : " ");
        return "[" + col + bar + "\033[0m]";
    }

    [[nodiscard]] bool isEnabled() const { return enabled_; }
};

static ColorSupport g_colors;

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

    [[nodiscard]] size_t getAllocationSize() const {
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
    std::cout << "\nPress ENTER to continue...";
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

void printSuccess(const std::string &msg) { std::cout << g_colors.green("[OK] ") << msg << "\n"; }

void printError(const std::string &msg, const std::string &hint = "") {
    std::cout << g_colors.red("[ERROR] ") << msg << "\n";
    if (!hint.empty()) std::cout << g_colors.dim("  Hint: " + hint) << "\n";
}

void printWarning(const std::string &msg) { std::cout << g_colors.yellow("[WARN] ") << msg << "\n"; }
void printInfo(const std::string &msg) { std::cout << g_colors.cyan("[INFO] ") << msg << "\n"; }

class ProgressTracker {
    std::chrono::steady_clock::time_point start_ = std::chrono::steady_clock::now();
    int total_;
    std::string op_;
    bool showProgress_;

public:
    ProgressTracker(int t, std::string o, bool show = true)
        : total_(t), op_(std::move(o)), showProgress_(show && t > 5) {
    }

    void update(int cur) const {
        if (!showProgress_) return;
        float p = total_ > 0 ? float(cur) / total_ : 0;
        std::cout << "\r" << op_ << ": " << g_colors.progressBar(p) << " "
                << std::fixed << std::setprecision(1) << p * 100 << "% (" << cur << "/" << total_ << ")";
        if (cur > 0 && cur < total_) {
            auto el = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start_).count();
            if (el > 0) {
                int rem = static_cast<int>((total_ - cur) * el / cur);
                std::cout << " ETA:" << rem / 60 << ":" << std::setw(2) << std::setfill('0')
                        << rem % 60 << std::setfill(' ');
            }
        }
        std::cout << "     ";
        std::cout.flush();
    }

    void finish() const {
        if (showProgress_)
            std::cout << "\r" << op_ << ": " << g_colors.progressBar(1.0) <<
                    " 100% Done!                \n";
        else printSuccess(op_ + " completed");
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
    std::string line(42, '=');
    std::cout << "+" << line << "+\n|" << std::string((42 - title.length()) / 2, ' ')
            << g_colors.bold(title) << std::string((43 - title.length()) / 2, ' ')
            << "|\n+" << line << "+\n\n";
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

// ==================== Command History ====================

class CommandHistory {
    std::deque<std::string> history_;
    size_t maxSize_ = 100;
    int position_ = -1;

public:
    void add(const std::string &cmd) {
        if (cmd.empty() || (!history_.empty() && history_.back() == cmd)) return;
        history_.push_back(cmd);
        if (history_.size() > maxSize_) history_.pop_front();
        position_ = -1;
    }

    std::string navigateUp(const std::string &current) {
        if (history_.empty()) return current;
        if (position_ == -1) position_ = history_.size();
        if (position_ > 0) position_--;
        return history_[position_];
    }

    std::string navigateDown(const std::string &current) {
        if (history_.empty() || position_ == -1) return current;
        if (position_ < (int) history_.size() - 1) {
            position_++;
            return history_[position_];
        }
        position_ = -1;
        return "";
    }

    void resetPosition() { position_ = -1; }
};

// ==================== Line Editor ====================

class LineEditor {
    iNode *node_;
    std::string cwd_, line_;
    size_t cursor_ = 0;
    bool useFs_ = false;
    CommandHistory history_;

    [[nodiscard]] std::string getLastToken() const {
        const auto p = line_.rfind(' ');
        return p == std::string::npos ? line_ : line_.substr(p + 1);
    }

    [[nodiscard]] size_t getLastTokenStart() const {
        auto p = line_.rfind(' ');
        return p == std::string::npos ? 0 : p + 1;
    }

    static std::vector<std::string> getFsCompletions(const std::string &partial) {
        std::vector<std::string> c;
        std::string dir, pre;
        const auto ls = partial.rfind('/');
        const auto bs = partial.rfind('\\');
        const auto sep = (ls != std::string::npos && bs != std::string::npos)
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
                if (pre.empty() || e.name.find(pre) == 0)
                    c.push_back(dir + e.name + (e.isDirectory ? "/" : ""));
        } catch (...) {
        }
        std::sort(c.begin(), c.end());
        return c;
    }

    [[nodiscard]] std::vector<std::string> getLbCompletions(const std::string &partial) const {
        std::vector<std::string> c;
        if (!node_) return c;
        std::string dir, pre;
        const auto ls = partial.rfind('/');
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
            if (pre.empty() || e.plainName.find(pre) == 0)
                c.push_back(
                    (ls != std::string::npos ? partial.substr(0, ls + 1) : "") + e.plainName + (e.isFile ? "" : "/"));
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

    void handleHistory(bool up, const std::string &pr) {
        line_ = up ? history_.navigateUp(line_) : history_.navigateDown(line_);
        cursor_ = line_.length();
        redraw(pr);
    }

public:
    explicit LineEditor(iNode *n = nullptr, std::string c = "/") : node_(n), cwd_(std::move(c)), useFs_(n == nullptr) {
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
        history_.resetPosition();
        std::cout << pr;
        std::cout.flush();
#ifdef _WIN32
        while (true) {
            if (int ch = _getch(); ch == '\r' || ch == '\n') {
                std::cout << "\n";
                history_.add(line_);
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
                } else if (ch == 72) handleHistory(true, pr);
                else if (ch == 80) handleHistory(false, pr);
            } else if (ch >= 32) {
                line_.insert(cursor_++, 1, char(ch));
                redraw(pr);
            }
        }
#else
        termios o, n;
        tcgetattr(STDIN_FILENO, &o);
        n = o;
        n.c_lflag &= ~(ICANON | ECHO);
        n.c_cc[VMIN] = 1;
        n.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &n);
        while (true) {
            char ch;
            read(STDIN_FILENO, &ch, 1);
            if (ch == '\n' || ch == '\r') {
                std::cout << "\n";
                tcsetattr(STDIN_FILENO, TCSANOW, &o);
                history_.add(line_);
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
                    } else if (s[1] == 'A') handleHistory(true, pr);
                    else if (s[1] == 'B') handleHistory(false, pr);
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

    // Note: preallocate() removed from new iNode interface
    if (showProg && batch.fileCount > 5) {
        printInfo("Processing " + formatSize(batch.getAllocationSize()) + " of data...");
    }

    int proc = 0;
    const int tot = static_cast<int>(batch.entries.size());
    const ProgressTracker prog(tot, "Encrypting", showProg);

    for (const auto &[fsPath, internalPath, size, isDirectory]: batch.entries) {
        if (isDirectory) {
            node->addDirectory(internalPath);
        } else if (size > 0) {
            auto [sz, buf] = Filesystem::readFile(fsPath);
            if (sz > 0 && !buf.empty())
                try {
                    node->addFile(internalPath, buf.data(), sz);
                } catch (const std::exception &ex) {
                    printError("Failed: " + internalPath, ex.what());
                }
        }
        prog.update(++proc);
    }
    prog.finish();
    return true;
}

// ==================== Help System ====================

struct CommandHelp {
    std::string name;
    std::string args;
    std::string description;
};

const std::vector<CommandHelp> CLI_COMMANDS = {
    {"ls", "[path]", "List directory contents"},
    {"cd", "<path>", "Change current directory"},
    {"pwd", "", "Print working directory"},
    {"cat", "<file>", "Display file contents"},
    {"rm", "<path>", "Remove file or directory (with confirmation)"},
    {"mkdir", "<path>", "Create a new directory"},
    {"mv", "<src> <dst>", "Move or rename a file/directory"},
    {"cp", "<src> <dst>", "Copy a file or directory"},
    {"rename", "<path> <name>", "Rename a file or directory"},
    {"find", "<pattern>", "Search for files matching pattern"},
    {"tree", "[path]", "Display directory tree structure"},
    {"extract", "[src] <dst>", "Export files to filesystem"},
    {"add", "<file> [path]", "Add file or directory from filesystem"},
    {"info", "<path>", "Show detailed information about a path"},
    {"limit", "[n]", "Set/show max items displayed in ls"},
    {"clear", "", "Clear the terminal screen"},
    {"help", "[cmd]", "Show this help or help for specific command"},
    {"exit", "", "Exit CLI mode and return to menu"},
};

void printHelp(const std::string &cmd = "") {
    if (cmd.empty()) {
        std::cout << g_colors.bold("\nAvailable Commands:\n\n");
        for (const auto &c: CLI_COMMANDS) {
            std::cout << "  " << g_colors.green(c.name);
            if (!c.args.empty()) std::cout << " " << g_colors.dim(c.args);
            std::cout << "\n      " << c.description << "\n";
        }
        std::cout << "\n" << g_colors.dim("Use TAB for auto-completion, UP/DOWN for command history\n");
    } else {
        for (const auto &c: CLI_COMMANDS) {
            if (c.name == cmd) {
                std::cout << "\n" << g_colors.bold(c.name);
                if (!c.args.empty()) std::cout << " " << c.args;
                std::cout << "\n  " << c.description << "\n";
                return;
            }
        }
        printError("Unknown command: " + cmd, "Type 'help' to see available commands");
    }
}

// ==================== Menu Functions ====================

void showMainMenu();

void openLockbox();

void createLockbox();

void encryptText();

void decryptText();

void managementMenu(iNode *node);

void cliMode(iNode *node);

void printUsage(const char *prog);

int handleArgs(int argc, char *argv[]);

void showMainMenu() {
    while (true) {
        printHeader("LOCKBOX - Main Menu");
        std::cout << "  [1] Open LockBox\n  [2] Create LockBox\n  [3] Encrypt text\n"
                << "  [4] Decrypt text\n  [0] Exit\n\n>> ";
        std::string ch;
        std::getline(std::cin, ch);
        if (ch == "1") openLockbox();
        else if (ch == "2") createLockbox();
        else if (ch == "3") encryptText();
        else if (ch == "4") decryptText();
        else if (ch == "0") {
            std::cout << "Goodbye!\n";
            return;
        } else {
            printError("Invalid choice", "Enter a number between 0-4");
            pressEnterToContinue();
        }
    }
}

void openLockbox() {
    printHeader("Open LockBox");
    auto path = getPathWithCompletion("LockBox path: ");
    if (path.empty()) {
        printError("No path specified", "Enter the path to your LockBox file");
        pressEnterToContinue();
        return;
    }
    if (!Filesystem::exists(path)) {
        printError("File not found: " + path, "Check the path and try again");
        pressEnterToContinue();
        return;
    }
    if (Filesystem::isDirectory(path)) {
        printError("Path is a directory", "Specify a LockBox file, not a directory");
        pressEnterToContinue();
        return;
    }

    auto pwd = getPassword();
    if (pwd.empty()) {
        printError("Empty password", "Password is required to open a LockBox");
        pressEnterToContinue();
        return;
    }

    auto *oes = new OES();
    oes->set_key(const_cast<char *>(pwd.c_str()));
    oes->extendWKey(OES_NUM_OF_BLOCKS);
    try {
        auto *node = new iNode(path, oes);
        printSuccess("LockBox opened successfully!");
        pressEnterToContinue();
        managementMenu(node);
        delete node;
    } catch (const std::exception &e) {
        printError("Failed to open LockBox", "Wrong password or corrupted file");
        pressEnterToContinue();
    }
    delete oes;
}

void createLockbox() {
    printHeader("Create LockBox");
    const auto src = getPathWithCompletion("Source path: ");
    if (src.empty() || !Filesystem::exists(src)) {
        printError("Invalid source path", "Specify an existing file or directory");
        pressEnterToContinue();
        return;
    }
    auto dst = getPathWithCompletion("Destination path: ");
    if (dst.empty()) {
        printError("Invalid destination", "Specify where to save the LockBox");
        pressEnterToContinue();
        return;
    }
    if (Filesystem::exists(dst)) {
        std::cout << "File exists. Overwrite? (y/n): ";
        std::string c;
        std::getline(std::cin, c);
        if (c != "y" && c != "Y") {
            printInfo("Operation cancelled");
            pressEnterToContinue();
            return;
        }
    }

    auto pwd = getPassword();
    if (pwd.empty()) {
        printError("Empty password");
        pressEnterToContinue();
        return;
    }
    if (pwd.length() < 8) {
        printWarning("Password is short (< 8 chars).");
    }
    auto pwd2 = getPassword("Confirm password: ");
    if (pwd != pwd2) {
        printError("Passwords do not match");
        pressEnterToContinue();
        return;
    }

    printInfo("Scanning files...");
    const PreCalculatedBatch batch = Filesystem::isDirectory(src)
                                         ? calculateDirectory(src)
                                         : calculateSingleFile(src, Filesystem::getFilename(src));
    std::cout << "  Directories: " << batch.dirCount << " | Files: " << batch.fileCount
            << " | Size: " << formatSize(batch.totalSize) << "\n\n";

    auto *oes = new OES();
    oes->set_key(const_cast<char *>(pwd.c_str()));
    oes->extendWKey(OES_NUM_OF_BLOCKS);
    try {
        auto *node = new iNode(dst, oes);
        insertBatchIntoLockbox(node, batch, true);
        printInfo("Saving LockBox...");
        node->save();
        printSuccess("LockBox created successfully!");
        pressEnterToContinue();
        managementMenu(node);
        delete node;
    } catch (const std::exception &e) {
        printError("Failed to create LockBox", e.what());
        pressEnterToContinue();
    }
    delete oes;
}

void encryptText() {
    printHeader("Encrypt Text");
    auto txt = getInput("Text to encrypt: ");
    if (txt.empty()) {
        printError("No text provided");
        pressEnterToContinue();
        return;
    }
    const auto pwd = getPassword();
    if (pwd.empty()) {
        printError("Empty password");
        pressEnterToContinue();
        return;
    }
    auto iv = getInput("IV (optional, press Enter to skip): ");

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
                printSuccess("Encrypted:");
                std::cout << "\n" << h << "\n";
                free(h);
            }
        }
    } catch (const std::exception &e) { printError("Encryption failed", e.what()); }
    delete oes;
    pressEnterToContinue();
}

void decryptText() {
    printHeader("Decrypt Text");
    auto hex = getInput("Hex ciphertext: ");
    if (hex.empty()) {
        printError("No ciphertext provided");
        pressEnterToContinue();
        return;
    }
    auto pwd = getPassword();
    if (pwd.empty()) {
        printError("Empty password");
        pressEnterToContinue();
        return;
    }
    auto iv = getInput("IV (optional, press Enter to skip): ");

    auto *ib = importBlock(hex.c_str(), hex.length(), OES_TYPE_HEX);
    if (!ib) {
        printError("Invalid hex format", "Ensure the ciphertext is valid hexadecimal");
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
        printSuccess("Decrypted:");
        std::cout << "\n";
        std::cout.write(reinterpret_cast<char *>(r.first), r.second);
        std::cout << "\n";
        delete[] r.first;
    } else { printError("Decryption failed", "Wrong password or corrupted data"); }
    delete oes;
    pressEnterToContinue();
}

void managementMenu(iNode *node) {
    while (true) {
        printHeader("LockBox Management");
        node->printStats();
        std::cout << "\n  [1] Extract   [2] CLI Mode   [3] Search   [4] Defragment\n"
                << "  [5] View Log  [6] Clear Log  [0] Save & Exit\n\n>> ";
        std::string cmd;
        std::getline(std::cin, cmd);
        auto tk = splitCommand(cmd);
        if (tk.empty()) continue;

        if (tk[0] == "0") {
            node->save();
            printSuccess("LockBox saved successfully!");
            pressEnterToContinue();
            return;
        }

        if (tk[0] == "1") {
            auto pp = tk.size() > 1 ? tk[1] : "";
            auto dest = getPathWithCompletion("Destination folder: ");
            if (dest.empty()) {
                printError("No destination specified");
                pressEnterToContinue();
                continue;
            }
            if (!Filesystem::exists(dest)) Filesystem::createDirectory(dest, true);
            try {
                node->exportTo(dest, pp);
                printSuccess("Extracted to " + dest);
            } catch (const std::exception &e) { printError("Extraction failed", e.what()); }
            pressEnterToContinue();
        } else if (tk[0] == "2") cliMode(node);
        else if (tk[0] == "3") {
            if (tk.size() < 2) { printError("No search term", "Usage: 3 <filename>"); } else {
                auto r = node->search(tk[1], false);
                if (r.empty()) printInfo("No results found for: " + tk[1]);
                else {
                    printSuccess("Found " + std::to_string(r.size()) + " result(s):");
                    for (const auto &p: r)
                        std::cout << "  " << (node->exists(p, true) ? "📄 " : "📁 ") << p << "\n";
                }
            }
            pressEnterToContinue();
        } else if (tk[0] == "4") {
            printInfo("Running defragmentation...");
            if (node->defragment()) printSuccess("Defragmentation completed");
            else printError("Defragmentation failed");
            pressEnterToContinue();
        } else if (tk[0] == "5") {
            std::cout << "\n" << g_colors.bold("=== Activity Log ===") << "\n"
                    << node->getLog() << g_colors.bold("====================") << "\n"
                    << "Log size: " << formatSize(node->getLogSize()) << "\n";
            pressEnterToContinue();
        } else if (tk[0] == "6") {
            std::cout << "Clear activity log? (y/n): ";
            std::string c;
            std::getline(std::cin, c);
            if (c == "y" || c == "Y") {
                node->clearLog();
                printSuccess("Log cleared");
            }
            pressEnterToContinue();
        } else {
            printError("Invalid option");
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
            std::cout << "  (empty directory)\n";
            return;
        }
        // Sort: directories first (isFile=false), then by name
        std::sort(ent.begin(), ent.end(), [](const iNode::DirEntry &a, const iNode::DirEntry &b) {
            return a.isFile != b.isFile ? a.isFile < b.isFile : a.plainName < b.plainName;
        });
        int sh = 0;
        for (const auto &e: ent) {
            if (sh >= maxIt) {
                std::cout << g_colors.dim("  ... " + std::to_string(ent.size() - maxIt) + " more items\n");
                break;
            }
            std::cout << (e.isFile ? "  📄 " : "  📁 ") << e.plainName
                    << (e.isFile ? " (" + formatSize(e.size) + ")" : "/") << "\n";
            sh++;
        }
        std::cout << g_colors.dim("Total: " + std::to_string(ent.size()) + " items\n");
    };

    clearScreen();
    std::cout << g_colors.bold("\n=== LockBox CLI Mode ===\n")
            << g_colors.dim("Type 'help' for commands, 'exit' to return to menu\n\n");

    while (true) {
        ed.setCwd(cwd);
        std::string prompt = g_colors.boldGreen("lockbox") + ":" + g_colors.boldBlue(cwd) + "$ ";
        auto cl = ed.readLine(prompt);
        auto tk = splitCommand(cl);
        if (tk.empty()) continue;
        std::string cmd = tk[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

        if (cmd == "exit" || cmd == "quit") return;

        if (cmd == "help") printHelp(tk.size() > 1 ? tk[1] : "");
        else if (cmd == "clear" || cmd == "cls") clearScreen();
        else if (cmd == "pwd") std::cout << cwd << "\n";
        else if (cmd == "ls") {
            auto td = tk.size() > 1 ? toDisp(tk[1]) : cwd;
            auto tp = toInternalPath(td);
            if (!tp.empty() && !node->exists(tp, false)) {
                printError("Directory not found: " + td);
                continue;
            }
            std::cout << g_colors.bold(td + ":\n");
            listDir(tp);
        } else if (cmd == "cd") {
            if (tk.size() < 2 || tk[1] == "/") cwd = "/";
            else {
                auto nd = toDisp(tk[1]);
                auto np = toInternalPath(nd);
                if (nd != "/" && !np.empty() && !node->exists(np, false)) {
                    printError("Directory not found: " + nd, "Use 'ls' to see available directories");
                    continue;
                }
                cwd = nd;
            }
        } else if (cmd == "cat") {
            if (tk.size() < 2) {
                printError("Missing argument", "Usage: cat <filename>");
                continue;
            }
            auto tp = toInt(tk[1]);
            if (!node->exists(tp, true)) {
                printError("File not found: " + tk[1]);
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
                printError("Missing argument", "Usage: rm <path>");
                continue;
            }
            auto tp = toInt(tk[1]);
            if (!node->exists(tp, true) && !node->exists(tp, false)) {
                printError("Not found: " + tk[1]);
                continue;
            }
            std::cout << "Delete '" << tk[1] << "'? (y/n): ";
            std::string c;
            std::getline(std::cin, c);
            if (c == "y" || c == "Y") {
                if (node->remove(tp)) printSuccess("Deleted: " + tk[1]);
                else printError("Failed to delete");
            } else printInfo("Cancelled");
        } else if (cmd == "mkdir") {
            if (tk.size() < 2) {
                printError("Missing argument", "Usage: mkdir <dirname>");
                continue;
            }
            if (node->addDirectory(toInt(tk[1])) != 0) printSuccess("Directory created: " + tk[1]);
            else printError("Failed to create directory", "Check if path already exists");
        } else if (cmd == "mv") {
            if (tk.size() < 3) {
                printError("Missing arguments", "Usage: mv <source> <destination>");
                continue;
            }
            if (node->move(toInt(tk[1]), toInt(tk[2]))) printSuccess("Moved successfully");
            else printError("Move failed", "Check that source exists and destination is valid");
        } else if (cmd == "cp") {
            if (tk.size() < 3) {
                printError("Missing arguments", "Usage: cp <source> <destination>");
                continue;
            }
            if (node->copy(toInt(tk[1]), toInt(tk[2]))) printSuccess("Copied successfully");
            else printError("Copy failed", "Check that source exists");
        } else if (cmd == "rename") {
            if (tk.size() < 3) {
                printError("Missing arguments", "Usage: rename <path> <newname>");
                continue;
            }
            if (node->rename(toInt(tk[1]), tk[2])) printSuccess("Renamed successfully");
            else printError("Rename failed");
        } else if (cmd == "find") {
            if (tk.size() < 2) {
                printError("Missing argument", "Usage: find <pattern>");
                continue;
            }
            if (auto r = node->search(tk[1], false); r.empty()) printInfo("No matches found for: " + tk[1]);
            else {
                printSuccess("Found " + std::to_string(r.size()) + " match(es):");
                for (const auto &x: r) std::cout << "  " << (node->exists(x, true) ? "📄 " : "📁 ") << x << "\n";
            }
        } else if (cmd == "tree") {
            auto td = tk.size() > 1 ? toDisp(tk[1]) : cwd;
            auto tp = toInternalPath(td);
            if (!tp.empty() && !node->exists(tp, false)) {
                printError("Directory not found: " + td);
                continue;
            }
            std::cout << g_colors.bold(td) << "\n";
            std::function<void(const std::string &, const std::string &)> pt = [&
                    ](const std::string &pp, const std::string &pf) {
                auto ent = node->listDirectory(pp);
                // Sort: directories first (isFile=false), then by name
                std::sort(ent.begin(), ent.end(), [](const iNode::DirEntry &a, const iNode::DirEntry &b) {
                    return a.isFile != b.isFile ? a.isFile < b.isFile : a.plainName < b.plainName;
                });
                for (size_t i = 0; i < ent.size(); i++) {
                    bool last = i == ent.size() - 1;
                    std::cout << pf << (last ? "└── " : "├── ") << (ent[i].isFile ? "📄 " : "📁 ")
                            << ent[i].plainName << (ent[i].isFile ? "" : "/") << "\n";
                    if (!ent[i].isFile)
                        pt(pp.empty() ? ent[i].plainName : pp + "/" + ent[i].plainName,
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
                printError("Missing arguments", "Usage: extract [source] <destination>");
                continue;
            }
            if (!Filesystem::exists(ep)) Filesystem::createDirectory(ep, true);
            try {
                node->exportTo(ep, pp);
                printSuccess("Extracted to: " + ep);
            } catch (const std::exception &e) { printError("Extraction failed", e.what()); }
        } else if (cmd == "a" || cmd == "add") {
            if (tk.size() < 2) {
                printError("Missing arguments", "Usage: add <external_path> [internal_path]");
                continue;
            }
            const auto &ext = tk[1];
            if (!Filesystem::exists(ext)) {
                printError("File not found: " + ext);
                continue;
            }
            std::string fn = Filesystem::getFilename(ext), ip;
            if (tk.size() >= 3) {
                auto &ia = tk[2];
                if (!ia.empty() && ia.back() == '/') ip = toInt(ia + fn);
                else if (node->exists(toInt(ia), false)) ip = toInt(ia + "/" + fn);
                else ip = toInt(ia);
            } else ip = toInt(fn);
            printInfo("Scanning...");
            PreCalculatedBatch batch;
            if (Filesystem::isDirectory(ext)) batch = calculateDirectory(ext);
            else batch = calculateSingleFile(ext, ip);
            std::cout << "  Size: " << formatSize(batch.totalSize) << " | Files: " << batch.fileCount << "\n";
            if (Filesystem::isDirectory(ext))
                for (auto &e: batch.entries) e.internalPath = (ip.empty() ? "" : ip + "/") + e.internalPath;
            insertBatchIntoLockbox(node, batch, true);
        } else if (cmd == "limit") {
            if (tk.size() < 2) std::cout << "Current limit: " << maxIt << " items\n";
            else {
                try {
                    maxIt = std::max(1, std::stoi(tk[1]));
                    printSuccess("Limit set to " + std::to_string(maxIt));
                } catch (...) { printError("Invalid number", "Usage: limit <number>"); }
            }
        } else if (cmd == "info") {
            if (tk.size() < 2) {
                printError("Missing argument", "Usage: info <path>");
                continue;
            }
            auto td = toDisp(tk[1]);
            auto tp = toInternalPath(td);
            bool isF = node->exists(tp, true);
            if (bool isD = !isF && (td == "/" || tp.empty() || node->exists(tp, false)); !isF && !isD) {
                printError("Not found: " + td);
                continue;
            }
            std::cout << "\n  Path: " << td << "\n  Type: " << (isF ? "File" : "Directory") << "\n";
        } else printError("Unknown command: " + cmd, "Type 'help' for available commands");
    }
}

// ==================== Command Line Arguments ====================

void printUsage(const char *prog) {
    std::cout << g_colors.bold("LockBox\n\n")
            << "Usage:\n"
            << "  [no args]                        Interactive mode\n"
            << "  <source> <lockbox> <pass>        Create lockbox from source\n"
            << "  -e <lockbox> <dest> <pass>       Extract lockbox to destination\n"
            << "  -c <text> <password>             Encrypt text\n"
            << "  -d <hex> <password>              Decrypt hex ciphertext\n"
            << "  -h                               Show this help\n\n";
}

int handleArgs(int argc, char *argv[]) {
    const std::string arg1 = argv[1];

    if (arg1 == "-h" || arg1 == "--help") {
        printUsage(argv[0]);
        return 0;
    }

    if (arg1 == "-c" && argc >= 4) {
        auto *oes = new OES();
        oes->set_key(argv[3]);
        oes->extendWKey(OES_NUM_OF_BLOCKS);
        try {
            oes->load_data_raw(argv[2], strlen(argv[2]));
            oes->enc_adv();
            if (auto *cb = oes->get_cipherBlock(); cb && !cb->isNull()) {
                auto [d, s] = exportBlock(cb, OES_TYPE_HEX);
                if (const auto h = static_cast<char *>(d)) {
                    std::cout << h << "\n";
                    free(h);
                }
            }
        } catch (const std::exception &e) {
            printError("Encryption failed", e.what());
            delete oes;
            return 1;
        }
        delete oes;
        return 0;
    }

    if (arg1 == "-d" && argc >= 4) {
        auto *ib = importBlock(argv[2], strlen(argv[2]), OES_TYPE_HEX);
        if (!ib) {
            printError("Invalid hex input");
            return 1;
        }
        auto *oes = new OES();
        oes->set_key(argv[3]);
        oes->extendWKey(OES_NUM_OF_BLOCKS);
        oes->load_cipher_block(ib, true);
        oes->dec_adv();
        if (const auto *pb = oes->get_plainBlock(); pb && !pb->isNull()) {
            auto [data, size] = pb->toBytes();
            std::cout.write(reinterpret_cast<char *>(data), size);
            std::cout << "\n";
            delete[] data;
        } else {
            printError("Decryption failed");
            delete oes;
            return 1;
        }
        delete oes;
        return 0;
    }

    if (arg1 == "-e" && argc >= 5) {
        if (!Filesystem::exists(argv[2])) {
            printError("LockBox not found: " + std::string(argv[2]));
            return 1;
        }
        auto *oes = new OES();
        oes->set_key(argv[4]);
        oes->extendWKey(OES_NUM_OF_BLOCKS);
        try {
            auto *node = new iNode(argv[2], oes);
            if (!Filesystem::exists(argv[3])) Filesystem::createDirectory(argv[3], true);
            node->exportTo(argv[3], "");
            printSuccess("Extracted to: " + std::string(argv[3]));
            delete node;
        } catch (const std::exception &e) {
            printError("Export failed", e.what());
            delete oes;
            return 1;
        }
        delete oes;
        return 0;
    }

    if (argc >= 4) {
        if (!Filesystem::exists(argv[1])) {
            printError("Source not found: " + std::string(argv[1]));
            return 1;
        }
        printInfo("Scanning files...");
        const PreCalculatedBatch batch = Filesystem::isDirectory(argv[1])
                                             ? calculateDirectory(argv[1])
                                             : calculateSingleFile(argv[1], Filesystem::getFilename(argv[1]));
        std::cout << "  Files: " << batch.fileCount << " | Size: " << formatSize(batch.totalSize) << "\n";

        auto *oes = new OES();
        oes->set_key(argv[3]);
        oes->extendWKey(OES_NUM_OF_BLOCKS);
        try {
            auto *node = new iNode(argv[2], oes);
            insertBatchIntoLockbox(node, batch, true);
            node->save();
            printSuccess("LockBox created: " + std::string(argv[2]));
            delete node;
        } catch (const std::exception &e) {
            printError("Creation failed", e.what());
            delete oes;
            return 1;
        }
        delete oes;
        return 0;
    }

    printError("Invalid arguments");
    printUsage(argv[0]);
    return 1;
}

int main(const int argc, char *argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    if (argc > 1) return handleArgs(argc, argv);
    showMainMenu();
    return 0;
}
