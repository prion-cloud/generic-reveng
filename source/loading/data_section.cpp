#include <generic-reveng/loading/data_section.hpp>

static_assert(std::is_destructible_v<grev::data_section>);

static_assert(std::is_copy_constructible_v<grev::data_section>);
static_assert(std::is_copy_assignable_v<grev::data_section>);

static_assert(std::is_move_constructible_v<grev::data_section>);
static_assert(std::is_move_assignable_v<grev::data_section>);
