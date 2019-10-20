#include <decompilation/expression_block.hpp>

namespace dec
{
    std::vector<std::string> expression_block::to_string() const
    {
        std::vector<std::string> result;
        result.reserve(size());
        for (auto const& [key, value] : *this)
            result.push_back(key.to_string() + " := " + value.to_string());

        return result;
    }

    void expression_block::update(expression_block other)
    {
        for (auto const& [key, value] : *this)
        {
            for (auto& [other_key, other_value] : other)
                other_value = other_value.substitute(key, value);
        }
        other.merge(*this);

        swap(other);
    }

    expression& expression_block::operator[](expression const& key)
    {
        return try_emplace(key, key).first->second;
    }
    expression& expression_block::operator[](std::string const& key_name)
    {
        return operator[](expression(key_name));
    }

    expression const& expression_block::operator[](expression const& key) const
    {
        if (auto const entry = find(key); entry != end())
            return entry->second;

        return key;
    }

    bool expression_block::operator==(expression_block other) const
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
    bool expression_block::operator!=(expression_block const& other) const
    {
        return !operator==(other);
    }

    static_assert(std::is_destructible_v<expression_block>);

    static_assert(std::is_move_constructible_v<expression_block>);
    static_assert(std::is_move_assignable_v<expression_block>);

    static_assert(std::is_copy_constructible_v<expression_block>);
    static_assert(std::is_copy_assignable_v<expression_block>);
}
