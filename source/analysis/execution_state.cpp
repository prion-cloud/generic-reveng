#include <generic-reveng/analysis/execution_state.hpp>

namespace grev
{
    void execution_state::define(z3::expression key, z3::expression value)
    {
        // Override existing entry or insert new key/value pair
        if (auto const entry = find(key); entry != end())
        {
            if (key == value)
            {
                erase(entry);
                return;
            }

            entry->second = std::move(value);
        }
        else
        {
            if (key == value)
                return;

            emplace(std::move(key), std::move(value));
        }
    }

    std::unordered_set<std::uint32_t> execution_state::memory_dependencies() const
    {
        std::unordered_set<std::uint32_t> memory_dependencies;
        for (auto const& [key, value] : *this)
        {
            if (auto const key_reference = key.reference())
            {
                for (auto const& key_reference_dependency : key_reference->dependencies())
                {
                    if (auto const key_reference_dependency_reference = key_reference_dependency.reference())
                    if (auto const key_reference_dependency_reference_value = key_reference_dependency_reference->evaluate())
                        memory_dependencies.insert(*key_reference_dependency_reference_value);
                }
            }
            for (auto const& value_dependency : value.dependencies())
            {
                if (auto const value_dependency_reference = value_dependency.reference())
                if (auto const value_dependency_reference_value = value_dependency_reference->evaluate())
                    memory_dependencies.insert(*value_dependency_reference_value);
            }
        }

        return memory_dependencies;
    }

    void execution_state::resolve(execution_fork* const fork) const
    {
        if (empty())
            return;

        execution_fork resolved;
        for (auto entry = fork->begin(); entry != fork->end();)
        {
            auto entry_node = fork->extract(entry++);

            resolve(&entry_node.key());
            resolve(&entry_node.mapped());

            resolved.jump(std::move(entry_node.key()), std::move(entry_node.mapped()));
        }

        *fork = std::move(resolved);
    }
    void execution_state::resolve(execution_state* const state) const
    {
        if (empty())
            return;

        execution_state resolved;
        for (auto entry = state->begin(); entry != state->end();)
        {
            auto entry_node = state->extract(entry++);

            if (auto key_reference = entry_node.key().reference())
            {
                resolve(&*key_reference);
                entry_node.key() = key_reference->dereference();
            }
            resolve(&entry_node.mapped());

            resolved.insert(std::move(entry_node));
        }

        *state = std::move(resolved);
    }

    z3::expression const& execution_state::operator[](z3::expression const& key) const
    {
        const_iterator entry;
        if (auto key_reference = key.reference())
        {
            resolve(&*key_reference);
            entry = find(key_reference->dereference());
        }
        else
            entry = find(key);

        if (entry != end())
            return entry->second;

        return key;
    }

    execution_state execution_state::operator+=(execution_state other)
    {
        resolve(&other);

        for (auto entry = other.begin(); entry != other.end();)
        {
            auto entry_node = other.extract(entry++);
            define(std::move(entry_node.key()), std::move(entry_node.mapped()));
        }

        return *this;
    }

    void execution_state::resolve(z3::expression* expression) const
    {
        for (auto const& key : expression->dependencies())
            *expression = expression->resolve_dependency(key, operator[](key));
    }

    execution_state operator+(execution_state a, execution_state b)
    {
        return a += std::move(b);
    }
}

static_assert(std::is_destructible_v<grev::execution_state>);

static_assert(std::is_copy_constructible_v<grev::execution_state>);
static_assert(std::is_nothrow_move_constructible_v<grev::execution_state>);

static_assert(std::is_copy_assignable_v<grev::execution_state>);
static_assert(std::is_nothrow_move_assignable_v<grev::execution_state>);
