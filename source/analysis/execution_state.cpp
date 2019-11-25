#include <generic-reveng/analysis/execution_state.hpp>

namespace grev
{
    void execution_state::update(z3::expression key, z3::expression value)
    {
        insert_or_assign(std::move(key), std::move(value));
    }

    execution_fork execution_state::resolve(execution_fork source) const
    {
        execution_fork resolved;
        for (auto element = source.begin(); element != source.end();)
            resolved.insert(resolve(std::move(source.extract(element++).value())));

        return resolved;
    }
    execution_state execution_state::resolve(execution_state source) const
    {
        execution_state resolved;
        for (auto const& [key, value] : *this)
            resolved.update(key, value);
        for (auto element = source.begin(); element != source.end();)
        {
            auto resolved_element = source.extract(element++);

            if (auto const key_reference = resolved_element.key().reference())
                resolved_element.key() = resolve(*key_reference).dereference();

            resolved.update(std::move(resolved_element.key()), resolve(std::move(resolved_element.mapped())));
        }

        return resolved;
    }

    z3::expression const& execution_state::operator[](z3::expression const& key) const
    {
        if (auto const entry = find(key); entry != end())
            return entry->second;

        return key;
    }

    z3::expression execution_state::resolve(z3::expression value) const
    {
        for (auto const& key : value.dependencies())
        {
            const_iterator entry;
            if (auto key_reference = key.reference(); key_reference)
                entry = find(resolve(std::move(*key_reference)).dereference());
            else
                entry = find(key);

            if (entry != end())
                value = value.resolve_dependency(key, entry->second);
        }

        return value;
    }
}

static_assert(std::is_destructible_v<grev::execution_state>);

static_assert(std::is_copy_constructible_v<grev::execution_state>);
static_assert(std::is_nothrow_move_constructible_v<grev::execution_state>);

static_assert(std::is_copy_assignable_v<grev::execution_state>);
static_assert(std::is_nothrow_move_assignable_v<grev::execution_state>);
