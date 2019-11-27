#pragma once

#include <forward_list>

#include <generic-reveng/analysis/execution_fork.hpp>
#include <generic-reveng/analysis/execution_state.hpp>

namespace grev
{
    class execution_path : std::unordered_map<z3::expression, z3::expression const*>
    {
        const_iterator start_jump_;

        execution_state current_state_; // TODO Collect updates
        iterator current_jump_;

    public:

        explicit execution_path(std::uint32_t start_address);
        ~execution_path();

        execution_path(execution_path const& other);
        execution_path(execution_path&& other) noexcept;

        execution_path& operator=(execution_path other) noexcept;

        std::forward_list<execution_path> update(execution_state state, execution_fork jumps);

        std::optional<std::uint32_t> next_address() const;

        // >>-----
        std::vector<std::uint32_t> addresses() const; // Testing seam TODO
        // -----<<

    private:

        void step(z3::expression jump);
    };
}
