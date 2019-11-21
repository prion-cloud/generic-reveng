#include <type_traits>

#include <generic-reveng/analysis/z3/syntax_tree_base.hpp>

namespace grev::z3
{
    syntax_tree_base::syntax_tree_base() = default;

    Z3_context const& syntax_tree_base::context()
    {
        struct context
        {
            Z3_context native; // NOLINT [misc-non-private-member-variables-in-classes]

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

            context(context const& other) = delete;
            context& operator=(context const& other) = delete;

            context(context&& other) = delete;
            context& operator=(context&& other) = delete;
        };

        static context const context;
        return context.native;
    }
}

static_assert(std::is_destructible_v<grev::z3::syntax_tree_base>);

static_assert(std::is_copy_constructible_v<grev::z3::syntax_tree_base>);
static_assert(std::is_nothrow_move_constructible_v<grev::z3::syntax_tree_base>);

static_assert(std::is_copy_assignable_v<grev::z3::syntax_tree_base>);
static_assert(std::is_nothrow_move_assignable_v<grev::z3::syntax_tree_base>);
