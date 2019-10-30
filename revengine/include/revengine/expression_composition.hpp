#pragma once

#include <unordered_map>
#include <vector>

#include <revengine/expression.hpp>
#include <revengine/expression_fork.hpp>

namespace rev
{
    class expression_composition : std::unordered_map<expression, expression>
    {
        expression_fork jump_;

    public:

        void update(expression_composition expression_composition);

        void jump(expression location);

        expression_fork const& jump() const;

        expression& operator[](expression const& key);
        expression& operator[](std::string const& key_name);

        expression const& operator[](expression const& key) const;

        // TODO move to tests
        bool operator==(expression_composition other) const;
        bool operator!=(expression_composition const& other) const;
    };
}
