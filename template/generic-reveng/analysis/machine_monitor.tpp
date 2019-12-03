#include <climits>

#ifdef LINT
#include <generic-reveng/analysis/machine_monitor.hpp>
#endif

namespace grev
{
    template <typename Disassembler, typename Program>
    machine_monitor::machine_monitor(Disassembler const& disassembler, Program const& program)
    {
        auto& initial_path = paths_.emplace_front(program.start_address());

        std::forward_list<execution_path*> pending_paths;
        pending_paths.push_front(&initial_path);
        do
        {
            auto* const path = pending_paths.front();
            pending_paths.pop_front();

            // Follow the current path as far as possible (-> depth first search)
            for (auto [address, code] = std::pair<std::optional<std::uint32_t>, std::u8string_view> { };;)
            {
                // Go on with the next address if unambiguous
                if (auto next_address = path->next_address())
                {
                    // (Re-)extract code if the next address is the first one or not adjacent to the previous address
                    if (address != *next_address)
                    {
                        address = std::move(*next_address);
                        code = program[*address];
                    }
                }
                else break;

                // Stop if no (more) code is available
                if (code.empty())
                    break;

                // Disassemble next code
                auto update = disassembler(&*address, &code);

                execution_state memory_patch_state;
                for (auto const dependency_address : update.state.memory_dependencies())
                {
                    auto const dependency_data = program[dependency_address];

                    if (dependency_data.size() < sizeof(std::uint32_t)) // TODO Distinguish between different sizes
                        continue;

                    auto const dependency_value = *reinterpret_cast<std::uint32_t const*>(dependency_data.data());

                    memory_patch_state.define(
                        z3::expression(sizeof dependency_address * CHAR_BIT, dependency_address)
                            .dereference(sizeof dependency_value * CHAR_BIT),
                        z3::expression(sizeof dependency_value * CHAR_BIT, dependency_value));
                }

                // Step forward
                auto forked_paths = path->proceed(std::move(update), memory_patch_state);

                // Store and enqueue each forked path
                for (auto& forked_path : forked_paths)
                {
                    paths_.push_front(std::move(forked_path));
                    pending_paths.push_front(&paths_.front());
                }
            }
        }
        while (!pending_paths.empty());
    }
}

#ifdef LINT
#include <generic-reveng/disassembly/reil_disassembler.hpp>
#include <generic-reveng/loading/program.hpp>
template grev::machine_monitor::machine_monitor(grev::reil_disassembler const&, grev::program const&);
#endif
