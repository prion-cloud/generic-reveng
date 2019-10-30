#include <revengine/machine_impact.hpp>

namespace rev
{
    void machine_impact::update(machine_impact other)
    {
        // TODO

        for (auto const& [key, value] : *this)
        {
            for (auto& entry : other)
                entry.second.resolve(key, value);

            other.jump_.resolve(key, value);
        }
        other.merge(*this);

        swap(other);

        jump_ = other.jump_;
    }

    void machine_impact::jump(expression location)
    {
        jump_.fork(std::move(location));
    }

    expression_fork const& machine_impact::jump() const
    {
        return jump_;
    }

    expression& machine_impact::operator[](expression const& key)
    {
        return try_emplace(key, key).first->second;
    }
    expression& machine_impact::operator[](std::string const& key_name)
    {
        return operator[](expression::unknown(key_name));
    }

    expression const& machine_impact::operator[](expression const& key) const
    {
        if (auto const entry = find(key); entry != end())
            return entry->second;

        return key;
    }

    bool machine_impact::operator==(machine_impact other) const
    {
        constexpr std::equal_to<expression> equal_to;
        for (auto const& [key, value] : *this)
        {
            if (equal_to(key, value))
                continue;

            auto const search = other.find(key);
            if (search == other.end() || !equal_to(search->second, value))
                return false;

            other.erase(search);
        }
        for (auto const& [key, value] : other)
        {
            if (!equal_to(key, value))
                return false;
        }

        return true;
    }
    bool machine_impact::operator!=(machine_impact const& other) const
    {
        return !operator==(other);
    }

    static_assert(std::is_destructible_v<machine_impact>);

    static_assert(std::is_move_constructible_v<machine_impact>);
    static_assert(std::is_move_assignable_v<machine_impact>);

    static_assert(std::is_copy_constructible_v<machine_impact>);
    static_assert(std::is_copy_assignable_v<machine_impact>);
}
