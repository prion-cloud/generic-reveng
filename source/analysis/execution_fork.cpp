#include <generic-reveng/analysis/execution_fork.hpp>

namespace grev
{
    void execution_fork::jump(z3::expression condition, z3::expression destination)
    {
        if (condition == z3::expression::boolean_false())
            return;

        insert_or_assign(std::move(condition), std::move(destination));
    }

    bool execution_fork::impasse() const
    {
        return empty();
    }
}

static_assert(std::is_destructible_v<grev::execution_fork>);

static_assert(std::is_copy_constructible_v<grev::execution_fork>);
static_assert(std::is_nothrow_move_constructible_v<grev::execution_fork>);

static_assert(std::is_copy_assignable_v<grev::execution_fork>);
static_assert(std::is_nothrow_move_assignable_v<grev::execution_fork>);
