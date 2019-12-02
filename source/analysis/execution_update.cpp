#include <generic-reveng/analysis/execution_update.hpp>

static_assert(std::is_destructible_v<grev::execution_update>);

static_assert(std::is_copy_constructible_v<grev::execution_update>);
static_assert(std::is_nothrow_move_constructible_v<grev::execution_update>);

static_assert(std::is_copy_assignable_v<grev::execution_update>);
static_assert(std::is_nothrow_move_assignable_v<grev::execution_update>);
