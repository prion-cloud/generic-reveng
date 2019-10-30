#pragma once

#include <unordered_map>
#include <vector>

#include <revengine/expression.hpp>
#include <revengine/expression_fork.hpp>

namespace rev
{
    class machine_impact : std::unordered_map<expression, expression>
    {
        expression_fork jump_;

    public:

        void update(machine_impact other);

        void jump(expression location);

        expression_fork const& jump() const;

        expression& operator[](expression const& key);
        expression& operator[](std::string const& key_name);

        expression const& operator[](expression const& key) const;

        // TODO move to tests
        bool operator==(machine_impact other) const;
        bool operator!=(machine_impact const& other) const;
    };
}
