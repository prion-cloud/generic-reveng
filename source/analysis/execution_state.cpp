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

    std::unordered_set<z3::expression> execution_state::dependencies() const
    {
        std::unordered_set<z3::expression> dependencies;
        for (auto const& [key, value] : *this)
        {
            if (auto const key_reference = key.reference())
                dependencies.merge(key_reference->dependencies());
            dependencies.merge(value.dependencies());
        }

        return dependencies;
    }

    void execution_state::resolve(z3::expression* expression) const
    {
        for (auto const& key : expression->dependencies())
            *expression = expression->resolve_dependency(key, operator[](key));
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
                entry_node.key() = key_reference->dereference(entry_node.key().width());
            }
            resolve(&entry_node.mapped());

            resolved.insert(std::move(entry_node));
        }

        *state = std::move(resolved);
    }

    z3::expression execution_state::operator[](z3::expression key) const
    {
        if (auto key_reference = key.reference())
        {
            resolve(&*key_reference);
            key = key_reference->dereference(key.width());
        }

        if (auto const entry = find(key); entry != end())
            return entry->second;

        return key;
    }

    execution_state execution_state::operator+=(execution_state other)
    {
        resolve(&other);

        // TODO 'append' method (?)
        for (auto entry = other.begin(); entry != other.end();)
        {
            auto entry_node = other.extract(entry++);
            define(std::move(entry_node.key()), std::move(entry_node.mapped()));
        }

        return *this;
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
