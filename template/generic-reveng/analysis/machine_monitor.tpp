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

            std::optional<std::uint32_t> address;
            std::u8string_view data;
            while (true)
            {
                auto const next_address = path->next_address();

                if (!next_address)
                    break; // TODO patching (?)

                if (address != next_address)
                {
                    address = *next_address;
                    data = program[*address];
                }

                if (data.empty())
                    break;

                auto [state, jumps] = disassembler(&*address, &data); // TODO Beautify

                for (auto& new_path : path->update(std::move(state), std::move(jumps)))
                {
                    paths_.push_front(std::move(new_path));
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
