#pragma once

#include <forward_list>

#include <generic-reveng/analysis/machine_state_update.hpp>

namespace grev
{
    class execution_path : std::unordered_map<z3::expression, z3::expression const*>
    {
        const_iterator start_jump_;

        machine_state current_state_; // TODO Collect updates
        iterator current_jump_;

    public:

        explicit execution_path(std::uint64_t start_address);
        ~execution_path();

        execution_path(execution_path const& other);
        execution_path(execution_path&& other) noexcept;

        execution_path& operator=(execution_path other) noexcept;

        std::forward_list<execution_path> update(machine_state_update const& update);

        std::optional<std::uint64_t> current_address() const;

        // >>-----
        std::vector<std::uint64_t> addresses() const; // Testing seam TODO
        // -----<<

    private:

        void step(z3::expression jump);
    };
}
