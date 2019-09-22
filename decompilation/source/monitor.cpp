#include "monitor.hpp"

namespace dec
{
    z3::expr monitor::get(reil_arg_t const& arg)
    {
        constexpr unsigned size = 64;

        switch (arg.type)
        {
        case A_REG:
            if (auto const entry = impact_.find(arg.name); entry != impact_.end())
                return entry->second;
            return context_.bv_const(arg.name, size);
        case A_TEMP:
            if (auto const entry = impact_temp_.find(arg.name); entry != impact_temp_.end())
                return entry->second;
            return context_.bv_const(arg.name, size);
        case A_CONST:
            return context_.bv_val(static_cast<std::uint_fast64_t>(arg.val), size);
        default:
            throw std::invalid_argument("");
        }
    }
    void monitor::set(reil_arg_t const& arg, z3::expr expr)
    {
        switch (arg.type)
        {
        case A_REG:
            if (auto const entry = impact_.find(arg.name); entry != impact_.end())
                std::swap(entry->second, expr);
            else
                impact_.emplace(arg.name, std::move(expr));
            break;
        case A_TEMP:
            if (auto const entry = impact_temp_.find(arg.name); entry != impact_temp_.end())
                std::swap(entry->second, expr);
            else
                impact_temp_.emplace(arg.name, std::move(expr));
            break;
        default:
            throw std::invalid_argument("");
        }
    }

/*
    z3::expr& monitor::operator[](reil_arg_t const& arg)
    {
        switch (arg.type)
        {
        case A_REG:
            return try_emplace(arg.name, *context_).first->second;
        case A_TEMP:
            return temp_.try_emplace(arg.name, *context_).first->second;
        default:
            throw std::invalid_argument("");
        }
    }
    z3::expr monitor::operator[](reil_arg_t const& arg) const
    {
        constexpr unsigned size = 64;

        switch (arg.type)
        {
        case A_REG:
            if (auto const entry = find(arg.name); entry != end())
                return entry->second;
            return context_->bv_const(arg.name, size);
        case A_TEMP:
            if (auto const entry = temp_.find(arg.name); entry != temp_.end())
                return entry->second;
            return context_->bv_const(arg.name, size);
        case A_CONST:
            return context_->bv_val(static_cast<std::uint_fast64_t>(arg.val), size);
        default:
            throw std::invalid_argument("");
        }
    }
*/

    std::unordered_map<std::string, z3::expr> monitor::impact()
    {
        std::unordered_map<std::string, z3::expr> impact;

        impact_.swap(impact);
        impact_temp_.clear();

        return impact;
    }

    static_assert(std::is_destructible_v<monitor>);

    static_assert(!std::is_move_constructible_v<monitor>); // TODO
    static_assert(!std::is_move_assignable_v<monitor>); // TODO

    static_assert(!std::is_copy_constructible_v<monitor>); // TODO
    static_assert(!std::is_copy_assignable_v<monitor>); // TODO
}
