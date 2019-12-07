#include <climits>

#ifdef LINT
#include <generic-reveng/analysis/machine_monitor.hpp>
#endif

namespace grev
{
    template <typename Disassembler, typename Program>
    machine_monitor::machine_monitor(Disassembler const& disassembler, Program const& program)
    {
        auto& initial_path =
            execution_.emplace_front(z3::expression(sizeof(std::uint32_t) * CHAR_BIT, *program.entry_point_address()));

        std::forward_list<execution_path*> pending_paths;
        pending_paths.push_front(&initial_path);
        do
        {
            auto* const path = pending_paths.front();
            pending_paths.pop_front();

            // Follow the current path as far as possible (-> depth first search)
            for (auto [address, code] = std::pair<std::optional<std::uint32_t>, std::u8string_view> { };;)
            {
                // Proceed if jump is available
                if (auto jump = path->jump())
                {
                    memory_patch(program, jump->dependencies()).resolve(&*jump);

                    // Proceed if unambiguous
                    if (auto next_address = jump->evaluate())
                    {
                        // (Re-)extract code if the next address is the first one or not adjacent to the previous address
                        if (address != *next_address)
                        {
                            address = std::move(*next_address);
                            code = program[*address];
                        }
                    }
                    else break;
                }
                else break;

                // Stop if no (more) code is available
                if (code.empty())
                    break;

                // Disassemble next code
                auto update_execution = disassembler(&*address, &code);

                if (update_execution.empty())
                    break;

                std::forward_list<execution_path> resolved_update_execution;
                for (auto& update_path : update_execution)
                {
                    memory_patch(program, update_path.state().dependencies()).resolve(&update_path.state());

                    path->state().resolve(&update_path.condition());

                    if (update_path.condition() == z3::expression::boolean_false())
                        continue;

                    resolved_update_execution.push_front(std::move(update_path));
                }

                auto update_path = resolved_update_execution.begin();
                for (; std::next(update_path) != resolved_update_execution.end(); ++update_path)
                {
                    auto& next_path = execution_.emplace_front(*path);
                    pending_paths.push_front(&next_path);

                    next_path.proceed(std::move(*update_path));
                }

                path->proceed(std::move(*update_path));
            }
        }
        while (!pending_paths.empty());
    }

    template <typename Program>
    execution_state machine_monitor::memory_patch(Program const& program, std::unordered_set<z3::expression> const& dependencies)
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

            auto data = program[*address];

            auto const value_width = dependency.width();
            auto const value_width_bytes = (value_width - 1) / CHAR_BIT + 1; // TODO Possible underflow (?)

            if (data.size() < value_width_bytes)
                continue;

            std::uint32_t value { };
            for (data.remove_suffix(data.size() - value_width_bytes); !data.empty(); data.remove_suffix(1)) // Little endian
                value = (value << CHAR_BIT) + data.back();

            memory_patch.define(dependency, z3::expression(value_width, value));
        }

        return memory_patch;
    }
}

#ifdef LINT
#include <generic-reveng/disassembly/reil_disassembler.hpp>
#include <generic-reveng/loading/program.hpp>
template grev::machine_monitor::machine_monitor(grev::reil_disassembler const&, grev::program const&);
#endif
