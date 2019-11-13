#include <revengine/data_section.hpp>

static_assert(std::is_destructible_v<rev::data_section>);

static_assert(std::is_copy_constructible_v<rev::data_section>);
static_assert(std::is_copy_assignable_v<rev::data_section>);

static_assert(std::is_move_constructible_v<rev::data_section>);
static_assert(std::is_move_assignable_v<rev::data_section>);
