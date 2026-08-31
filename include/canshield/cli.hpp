#ifndef CANSHIELD_CLI_HPP
#define CANSHIELD_CLI_HPP

#include <cstdlib>
#include <string>
#include <vector>

namespace canshield {

// dead-simple flag parser: supports "--name value" and "--flag"
class Args {
public:
    Args(int argc, char** argv) {
        for (int i = 1; i < argc; ++i) tokens_.emplace_back(argv[i]);
    }
    bool has(const std::string& f) const {
        for (auto& t : tokens_) if (t == f) return true;
        return false;
    }
    std::string get(const std::string& f, const std::string& def = "") const {
        for (std::size_t i = 0; i + 1 < tokens_.size(); ++i)
            if (tokens_[i] == f) return tokens_[i + 1];
        return def;
    }
    long geti(const std::string& f, long def) const {
        std::string v = get(f);
        return v.empty() ? def : std::strtol(v.c_str(), nullptr, 0);
    }
    double getf(const std::string& f, double def) const {
        std::string v = get(f);
        return v.empty() ? def : std::strtod(v.c_str(), nullptr);
    }
private:
    std::vector<std::string> tokens_;
};

}  // namespace canshield

#endif
