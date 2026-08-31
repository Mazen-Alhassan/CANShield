#ifndef CANSHIELD_TEST_FRAMEWORK_HPP
#define CANSHIELD_TEST_FRAMEWORK_HPP

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace canshield {
namespace test {

struct Case {
    std::string name;
    std::function<void()> fn;
};

// Per-test failure counter, reset before each case.
inline int& current_failures() {
    static int f = 0;
    return f;
}

inline std::vector<Case>& registry() {
    static std::vector<Case> r;
    return r;
}

struct Registrar {
    Registrar(const std::string& name, std::function<void()> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

inline void report_failure(const char* file, int line, const std::string& msg) {
    ++current_failures();
    std::fprintf(stderr, "    FAIL %s:%d: %s\n", file, line, msg.c_str());
}

inline int run_all() {
    int passed = 0, failed = 0;
    for (auto& c : registry()) {
        current_failures() = 0;
        try {
            c.fn();
        } catch (const std::exception& e) {
            report_failure(__FILE__, __LINE__,
                           std::string("uncaught exception: ") + e.what());
        } catch (...) {
            report_failure(__FILE__, __LINE__, "uncaught non-std exception");
        }
        if (current_failures() == 0) {
            std::printf("[ PASS ] %s\n", c.name.c_str());
            ++passed;
        } else {
            std::printf("[ FAIL ] %s (%d assertion(s))\n", c.name.c_str(),
                        current_failures());
            ++failed;
        }
    }
    std::printf("\n==== %d passed, %d failed, %d total ====\n", passed, failed,
                passed + failed);
    return failed == 0 ? 0 : 1;
}

}  // namespace test
}  // namespace canshield

// --- Assertion macros -------------------------------------------------------
// Two-level indirection so __LINE__ expands before token pasting, giving each
// TEST_CASE in a file unique function/registrar identifiers.
#define CANSHIELD_CONCAT_(a, b) a##b
#define CANSHIELD_CONCAT(a, b) CANSHIELD_CONCAT_(a, b)

#define TEST_CASE(NAME)                                                      \
    static void CANSHIELD_CONCAT(canshield_test_fn_, __LINE__)();            \
    static ::canshield::test::Registrar CANSHIELD_CONCAT(                    \
        canshield_test_reg_, __LINE__)(                                      \
        NAME, &CANSHIELD_CONCAT(canshield_test_fn_, __LINE__));             \
    static void CANSHIELD_CONCAT(canshield_test_fn_, __LINE__)()

#define CHECK(COND)                                                          \
    do {                                                                     \
        if (!(COND)) {                                                       \
            ::canshield::test::report_failure(__FILE__, __LINE__,            \
                                              "CHECK(" #COND ")");           \
        }                                                                    \
    } while (0)

#define CHECK_EQ(A, B)                                                       \
    do {                                                                     \
        auto _a = (A);                                                       \
        auto _b = (B);                                                       \
        if (!(_a == _b)) {                                                   \
            std::ostringstream _os;                                          \
            _os << "CHECK_EQ(" #A ", " #B ") -> [" << _a << "] != [" << _b   \
                << "]";                                                      \
            ::canshield::test::report_failure(__FILE__, __LINE__, _os.str());\
        }                                                                    \
    } while (0)

#define CHECK_TRUE(COND) CHECK(COND)
#define CHECK_FALSE(COND) CHECK(!(COND))

#endif  // CANSHIELD_TEST_FRAMEWORK_HPP
