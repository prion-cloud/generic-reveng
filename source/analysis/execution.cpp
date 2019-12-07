#include <generic-reveng/analysis/execution.hpp>

static_assert(std::is_destructible_v<grev::execution>);

static_assert(std::is_copy_constructible_v<grev::execution>);
static_assert(std::is_nothrow_move_constructible_v<grev::execution>);

static_assert(std::is_copy_assignable_v<grev::execution>);
static_assert(std::is_nothrow_move_assignable_v<grev::execution>);
