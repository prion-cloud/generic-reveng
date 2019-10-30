#include <revengine/expression_fork.hpp>

namespace rev
{
    expression_fork::operator bool() const
    {
        return value_.has_value();
    }

    std::uint64_t expression_fork::operator*() const
    {
        return value_.value();
    }

    void expression_fork::fork(expression expression)
    {
        insert(std::move(expression));

        update_value();
    }

    void expression_fork::resolve(expression const& x, expression const& y)
    {
        std::unordered_set<expression> buf;
        swap(buf);

        for (auto const& expression : buf)
        {
            auto ex = buf.extract(expression);
            ex.value().resolve(x, y);
            insert(std::move(ex));
        }

        update_value();
    }

    void expression_fork::update_value()
    {
        if (size() != 1)
        {
            value_ = std::nullopt;
            return;
        }

        auto const& single = *begin();

        if (!single)
        {
            value_ = std::nullopt;
            return;
        }

        value_ = *single;
    }
}
