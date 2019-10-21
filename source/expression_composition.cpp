#include <decompilation/expression_composition.hpp>

namespace dec
{
    std::vector<std::string> expression_composition::to_string() const
    {
        std::vector<std::string> result;
        result.reserve(size());
        for (auto const& [key, value] : *this)
            result.push_back(key.to_string() + " := " + value.to_string());

        return result;
    }

    expression expression_composition::update(expression expression) const
    {
        for (auto const& key : expression.decompose())
        {
            if (auto const entry = find(key); entry != end())
                expression = expression.substitute(key, entry->second);
        }

        return expression;
    }
    expression_composition expression_composition::update(expression_composition const& expression_composition) const
    {
        auto updated = expression_composition;
        for (auto const& [key, value] : *this)
            updated.insert_or_assign(key, expression_composition.update(value));

        return updated;
    }

    expression& expression_composition::operator[](expression const& key)
    {
        return try_emplace(key, key).first->second;
    }
    expression& expression_composition::operator[](std::string const& key_name)
    {
        return operator[](expression(key_name));
    }

    expression const& expression_composition::operator[](expression const& key) const
    {
        if (auto const entry = find(key); entry != end())
            return entry->second;

        return key;
    }

    bool expression_composition::operator==(expression_composition other) const
    {
        for (auto const& [key, value] : *this)
        {
            if (key == value)
                continue;

            auto const search = other.find(key);
            if (search == other.end() || search->second != value)
                return false;

            other.erase(search);
        }
        for (auto const& [key, value] : other)
        {
            if (key != value)
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
