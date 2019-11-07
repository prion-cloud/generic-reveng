#include <type_traits>

#include <revengine/z3/ast_base.hpp>

namespace rev::z3
{
    ast_base::ast_base() = default;

    Z3_context const& ast_base::context()
    {
        struct context
        {
            Z3_context native;

            context()
            {
                auto const configuration = Z3_mk_config();

                native = Z3_mk_context_rc(configuration);

                Z3_del_config(configuration);
            }
            ~context()
            {
                Z3_del_context(native);
            }
        };

        static context const context;
        return context.native;
    }
}

static_assert(!std::is_constructible_v<rev::z3::ast_base>);
static_assert(std::is_destructible_v<rev::z3::ast_base>);

static_assert(std::is_copy_constructible_v<rev::z3::ast_base>);
static_assert(std::is_copy_assignable_v<rev::z3::ast_base>);

static_assert(std::is_move_constructible_v<rev::z3::ast_base>);
static_assert(std::is_move_assignable_v<rev::z3::ast_base>);
