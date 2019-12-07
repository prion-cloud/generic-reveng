#include <climits>

#ifdef LINT
#include <generic-reveng/analysis/machine_monitor.hpp>
#endif

namespace grev
{
    template <typename Disassembler>
    machine_monitor::machine_monitor(Disassembler const& disassembler, machine_program program) :
        program_(std::move(program))
    {
        auto& initial_path =
            execution_.emplace_front(z3::expression(sizeof(std::uint32_t) * CHAR_BIT, program_.entry_point_address()));

        std::forward_list<execution_path*> pending_paths;
        pending_paths.push_front(&initial_path);
        do
        {
            auto* const path = pending_paths.front();
            pending_paths.pop_front();

            // Follow the current path as far as possible (depth-first search)
            for (auto [address, code] = std::pair<std::optional<std::uint32_t>, std::u8string_view> { };;)
            {
                // Proceed if jump is available
                if (auto jump = path->jump())
                {
                    memory_patch(jump->dependencies()).resolve(&*jump);

                    // Proceed if unambiguous
                    if (auto next_address = jump->evaluate())
                    {
                        // (Re-)extract code if the next address is the first one or not adjacent to the previous address
                        if (address != *next_address)
                        {
                            address = std::move(*next_address);
                            code = program_[*address];
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
                    memory_patch(update_path.state().dependencies()).resolve(&update_path.state());

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
}

#ifdef LINT
#include <generic-reveng/disassembly/reil_disassembler.hpp>
template grev::machine_monitor::machine_monitor(grev::reil_disassembler const&, grev::machine_program);
#endif
