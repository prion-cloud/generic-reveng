#include <revengine/data_section.hpp>

namespace rev
{
    static_assert(std::is_destructible_v<data_section>);

    static_assert(std::is_move_constructible_v<data_section>);
    static_assert(std::is_move_assignable_v<data_section>);

    static_assert(std::is_copy_constructible_v<data_section>);
    static_assert(std::is_copy_assignable_v<data_section>);
}
