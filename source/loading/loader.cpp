#include "loader.hpp"

namespace grev
{
    loader::~loader() = default;
}

static_assert(std::is_abstract_v<grev::loader>);

static_assert(std::is_destructible_v<grev::loader>);

static_assert(!std::is_copy_constructible_v<grev::loader>);
static_assert(!std::is_nothrow_move_constructible_v<grev::loader>);

static_assert(std::is_copy_assignable_v<grev::loader>);
static_assert(std::is_nothrow_move_assignable_v<grev::loader>);
