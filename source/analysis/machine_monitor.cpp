#include <climits>

#include <generic-reveng/analysis/machine_monitor.hpp>

namespace grev
{
    // >>-----
    std::vector<std::vector<std::uint32_t>> machine_monitor::path_addresses() const
    {
        std::vector<std::vector<std::uint32_t>> path_addresses;
        for (auto const& path : execution_)
            path_addresses.push_back(path.addresses());

        return path_addresses;
    }
    // -----<<

    execution_state machine_monitor::memory_patch(std::unordered_set<z3::expression> const& dependencies) const
    {
        execution_state memory_patch;
        for (auto const& dependency : dependencies)
        {
            auto const dependency_reference = dependency.reference();

            // Needs to be a memory access
            if (!dependency_reference)
                continue;

            auto const address = dependency_reference->evaluate();

            // Needs to be an unambiguous number
            if (!address)
                continue;

            auto data = program_[*address];

            auto const value_width = dependency.width();
            auto const value_width_bytes = (value_width - 1) / CHAR_BIT + 1; // TODO Possible underflow (?)

            if (data.size() < value_width_bytes)
                continue;

            std::uint32_t value { };
            for (data.remove_suffix(data.size() - value_width_bytes); !data.empty(); data.remove_suffix(1)) // Little endian
                value = (value << std::uint8_t{CHAR_BIT}) + data.back();

            memory_patch.define(dependency, z3::expression(value_width, value));
        }

        return memory_patch;
    }
}

static_assert(std::is_destructible_v<grev::machine_monitor>);

static_assert(std::is_copy_constructible_v<grev::machine_monitor>);
static_assert(std::is_nothrow_move_constructible_v<grev::machine_monitor>);

static_assert(std::is_copy_assignable_v<grev::machine_monitor>);
static_assert(std::is_nothrow_move_assignable_v<grev::machine_monitor>);
