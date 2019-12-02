#include <generic-reveng/analysis/execution_state.hpp>

namespace grev
{
    void execution_state::define(z3::expression key, z3::expression value)
    {
        insert_or_assign(std::move(key), std::move(value));
    }

    execution_fork execution_state::resolve(execution_fork source) const
    {
        execution_fork resolved;
        for (auto element = source.begin(); element != source.end();)
            resolved.insert(resolve_value(std::move(source.extract(element++).value())));

        return resolved;
    }
    execution_state execution_state::resolve(execution_state source) const
    {
        execution_state resolved;
        for (auto element = source.begin(); element != source.end();)
        {
            auto element_node = source.extract(element++);

            element_node.key() = resolve_key(std::move(element_node.key()));
            element_node.mapped() = resolve_value(std::move(element_node.mapped()));

            resolved.insert(std::move(element_node));
        }
        for (auto const& [key, value] : *this)
            resolved.try_emplace(key, value);

        return resolved;
    }

    z3::expression const& execution_state::operator[](z3::expression const& key) const
    {
        if (auto const entry = find(resolve_key(key)); entry != end())
            return entry->second;

        return key;
    }

    z3::expression execution_state::resolve_key(z3::expression key) const
    {
        if (auto key_reference = key.reference())
            return resolve_value(std::move(*key_reference)).dereference();

        return key;
    }
    z3::expression execution_state::resolve_value(z3::expression value) const
    {
        for (auto const& key : value.dependencies())
            value = value.resolve_dependency(key, operator[](key));

        return value;
    }
}

static_assert(std::is_destructible_v<grev::execution_state>);

static_assert(std::is_copy_constructible_v<grev::execution_state>);
static_assert(std::is_nothrow_move_constructible_v<grev::execution_state>);

static_assert(std::is_copy_assignable_v<grev::execution_state>);
static_assert(std::is_nothrow_move_assignable_v<grev::execution_state>);
