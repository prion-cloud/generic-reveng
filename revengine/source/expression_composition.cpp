#include <revengine/expression_composition.hpp>

namespace rev
{
    void expression_composition::update(expression_composition expression_composition)
    {
        for (auto const& [key, value] : *this)
        {
            for (auto& entry : expression_composition)
                entry.second = entry.second.resolve(key, value);
        }
        expression_composition.merge(*this);

        swap(expression_composition);
    }

    expression& expression_composition::operator[](expression const& key)
    {
        return try_emplace(key, key).first->second;
    }
    expression& expression_composition::operator[](std::string const& key_name)
    {
        return operator[](expression::unknown(key_name));
    }

    expression const& expression_composition::operator[](expression const& key) const
    {
        if (auto const entry = find(key); entry != end())
            return entry->second;

        return key;
    }

    bool expression_composition::operator==(expression_composition other) const
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
    bool expression_composition::operator!=(expression_composition const& other) const
    {
        return !operator==(other);
    }

    static_assert(std::is_destructible_v<expression_composition>);

    static_assert(std::is_move_constructible_v<expression_composition>);
    static_assert(std::is_move_assignable_v<expression_composition>);

    static_assert(std::is_copy_constructible_v<expression_composition>);
    static_assert(std::is_copy_assignable_v<expression_composition>);
}
