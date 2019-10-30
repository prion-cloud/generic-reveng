#pragma once

#include <revengine/expression.hpp>

namespace rev
{
    class expression_fork : std::unordered_set<expression>
    {
        std::optional<std::uint64_t> value_;

    public:

        using std::unordered_set<expression>::begin;
        using std::unordered_set<expression>::end;

        operator bool() const;

        std::uint64_t operator*() const;

        void fork(expression expression);

        void resolve(expression const& x, expression const& y);

    private:

        void update_value();
    };
}
