#include <decompilation/expression_block.hpp>

namespace dec
{
    expression const& expression_block::operator[](expression const& key) const
    {
        if (auto const entry = find(key); entry != end())
            return entry->second;
        return key;
    }

    expression& expression_block::operator[](expression const& key)
    {
        return try_emplace(key, key).first->second;
    }
    expression& expression_block::operator[](std::string const& name)
    {
        return operator[](expression(name));
    }
}
