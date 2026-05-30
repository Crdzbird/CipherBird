#pragma once
/**
 * test_framework.hpp — lightweight zero-dependency test runner.
 *
 * All test .cpp files are compiled into a single binary.
 * __LINE__-based unique names require a double-expansion trick so that
 * __LINE__ is resolved BEFORE the ## paste operator sees it.
 */

#include <cryptolib/cryptolib.hpp>

#include <cstdio>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// ─── Token-paste helpers (required for __LINE__ to expand before pasting) ────
#define _CONCAT(a, b) a##b
#define CONCAT(a, b)  _CONCAT(a, b)

#define RST  "\033[0m"
#define BOLD "\033[1m"
#define GRN  "\033[32m"
#define RED  "\033[31m"
#define YLW  "\033[33m"
#define CYN  "\033[36m"
#define GRY  "\033[90m"

namespace test {

// ── Global state ──────────────────────────────────────────────────────────────
struct State {
    int  total  = 0;
    int  passed = 0;
    int  failed = 0;
    bool cur_ok = true;
    bool abort_ = false;
};
inline State g_state;

// ── Test registry ─────────────────────────────────────────────────────────────
using TestFn = std::function<void()>;
inline std::unordered_map<std::string, TestFn>& registry() {
    static std::unordered_map<std::string, TestFn> r;
    return r;
}
struct Registrar {
    Registrar(std::string name, TestFn fn) { registry()[std::move(name)] = std::move(fn); }
};

} // namespace test

// ── TEST macro ────────────────────────────────────────────────────────────────
// The double-indirection (CONCAT → _CONCAT) ensures __LINE__ expands to a
// number before ## pastes it, giving unique names across multiple .cpp files
// compiled into the same binary.
#define TEST(name) \
    static void        CONCAT(_test_fn_, __LINE__)(); \
    static ::test::Registrar CONCAT(_reg_, __LINE__)(name, CONCAT(_test_fn_, __LINE__)); \
    static void        CONCAT(_test_fn_, __LINE__)()

// ── Assertion macros ──────────────────────────────────────────────────────────
#define _FAIL_AT(expr, file, line) do { \
    ::test::g_state.cur_ok = false; \
    std::printf("      " RED "FAIL" RST " %s:%d  %s\n", file, line, expr); \
} while(0)

#define CHECK(expr)      do { if (!(expr)) _FAIL_AT(#expr, __FILE__, __LINE__); } while(0)
#define REQUIRE(expr)    do { if (!(expr)) { _FAIL_AT(#expr, __FILE__, __LINE__); ::test::g_state.abort_ = true; return; } } while(0)
#define CHECK_OK(r)      CHECK((r).is_ok())
#define CHECK_ERR(r)     CHECK((r).is_err())
#define CHECK_EQ(a, b)   CHECK((a) == (b))

// ── Suite / runner ────────────────────────────────────────────────────────────
namespace test {

inline void run_suite(std::string_view suite, std::function<void()> fn) {
    g_state.cur_ok = true;
    std::printf("\n" BOLD CYN "  %-22s" RST "\n", suite.data());
    fn();
}

inline void run(std::string_view name) {
    auto it = registry().find(std::string(name));
    if (it == registry().end()) {
        std::printf("    " YLW "SKIP" RST " %s\n", name.data());
        return;
    }
    g_state.cur_ok = true;
    g_state.abort_ = false;
    g_state.total++;

    it->second();

    if (g_state.cur_ok) { g_state.passed++; std::printf("    " GRN "✓" RST " %s\n", name.data()); }
    else                 { g_state.failed++; std::printf("    " RED "✗" RST " %s\n", name.data()); }
}

#define RUN(name) ::test::run(name)

inline int report() {
    std::printf("\n" BOLD "─────────────────────────────────────────\n");
    std::printf("  %d tests   " GRN "%d passed" RST "   ", g_state.total, g_state.passed);
    if (g_state.failed > 0) std::printf(RED "%d FAILED\n" RST, g_state.failed);
    else                    std::printf(GRN "0 failed\n" RST);
    std::printf(BOLD "─────────────────────────────────────────\n" RST);
    return g_state.failed > 0 ? 1 : 0;
}

inline std::span<const uint8_t> sv2sp(std::string_view s) {
    return { reinterpret_cast<const uint8_t*>(s.data()), s.size() };
}

} // namespace test
