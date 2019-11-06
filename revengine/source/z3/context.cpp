#include <climits>
#include <type_traits>

#include <revengine/z3/context.hpp>

namespace rev::z3
{
    context::context()
    {
        auto const config = Z3_mk_config();

        base_ = Z3_mk_context_rc(config);

        Z3_del_config(config);
    }

    context::~context()
    {
        Z3_del_context(base_);
    }

    context::operator Z3_context() const
    {
        return base_;
    }

    context const& context::instance()
    {
        static context instance;
        return instance;
    }
}

static_assert(std::is_destructible_v<rev::z3::context>);

static_assert(!std::is_copy_constructible_v<rev::z3::context>);
static_assert(!std::is_copy_assignable_v<rev::z3::context>);

static_assert(!std::is_move_constructible_v<rev::z3::context>); // TODO ?
static_assert(!std::is_move_assignable_v<rev::z3::context>); // TODO ?
