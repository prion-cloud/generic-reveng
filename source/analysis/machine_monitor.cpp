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

    std::unordered_map<std::uint32_t, std::forward_list<execution_state>> const& machine_monitor::import_calls() const
    {
        return import_calls_;
    }

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

            auto const value_width = dependency.width();
            auto const value_width_bytes = (value_width - 1) / CHAR_BIT + 1; // TODO Possible underflow (?)

            if (*address == 0x40336c)
            {
                memory_patch.define(dependency, z3::expression(value_width, 0x00000000));
                continue;
            }
            if (*address == 0x403370)
            {
                memory_patch.define(dependency, z3::expression(value_width, 0x00130000));
                continue;
            }
            if (*address == 0x40337c)
            {
                memory_patch.define(dependency, z3::expression(value_width, 0x00000001));
                continue;
            }
            if (*address == 0x403380)
            {
                memory_patch.define(dependency, z3::expression(value_width, 0x00000000));
                continue;
            }
            if (*address == 0x7ffe0014)
            {
                memory_patch.define(dependency, z3::expression(value_width, 0xed72313c));
                continue;
            }
            if (*address == 0x7ffe0018 || *address == 0x7ffe001c)
            {
                memory_patch.define(dependency, z3::expression(value_width, 0x01d5adc1));
                continue;
            }
            if (*address == 0x7ffe0300)
            {
                memory_patch.define(dependency, z3::expression(value_width, 0x7c90e4f0));
                continue;
            }

            auto data = program_[*address];

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
