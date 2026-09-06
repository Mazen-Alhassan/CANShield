#include "canshield/cli.hpp"
#include "test_framework.hpp"

using canshield::Args;

static const char* kArgv[] = {"prog",     "--iface", "vcan0", "--max-print",
                              "10",       "--rate",  "2.5",   "--verbose"};

TEST_CASE("Args::has finds a bare flag and rejects an absent one") {
    Args args(8, const_cast<char**>(kArgv));
    CHECK_TRUE(args.has("--verbose"));
    CHECK_FALSE(args.has("--missing"));
}

TEST_CASE("Args::get returns the value following a flag, else the default") {
    Args args(8, const_cast<char**>(kArgv));
    CHECK_EQ(args.get("--iface"), std::string("vcan0"));
    CHECK_EQ(args.get("--nope", "fallback"), std::string("fallback"));
    CHECK_EQ(args.get("--nope"), std::string(""));
}

TEST_CASE("Args::geti parses an integer, else the default") {
    Args args(8, const_cast<char**>(kArgv));
    CHECK_EQ(args.geti("--max-print", -1), 10L);
    CHECK_EQ(args.geti("--absent", 42), 42L);
}

TEST_CASE("Args::getf parses a float, else the default") {
    Args args(8, const_cast<char**>(kArgv));
    CHECK_TRUE(args.getf("--rate", -1.0) == 2.5);
    CHECK_TRUE(args.getf("--absent", 7.0) == 7.0);
}

TEST_CASE("Args ignores a trailing flag with no following value") {
    const char* argv[] = {"prog", "--dangling"};
    Args args(2, const_cast<char**>(argv));
    CHECK_TRUE(args.has("--dangling"));
    CHECK_EQ(args.get("--dangling", "def"), std::string("def"));
}

TEST_CASE("Args with no tokens returns defaults for everything") {
    const char* argv[] = {"prog"};
    Args args(1, const_cast<char**>(argv));
    CHECK_FALSE(args.has("--anything"));
    CHECK_EQ(args.geti("--x", 5), 5L);
}

int main() { return canshield::test::run_all(); }
