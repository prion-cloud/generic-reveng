#include <generic-reveng/analysis/data_section.hpp>

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

            std::optional<data_section> previous_data_section;
            while (true)
            {
                auto const current_address = path->current_address();

                if (!current_address)
                    break; // TODO patching (?)

                auto current_data_section = previous_data_section && *current_address == previous_data_section->address
                    ? std::move(*previous_data_section)
                    : program[*current_address];

                if (current_data_section.data.empty())
                    break;

                for (auto& new_path : path->update(disassembler(&current_data_section)))
                {
                    paths_.push_front(std::move(new_path));
                    pending_paths.push_front(&paths_.front());
                }

                previous_data_section = std::move(current_data_section);
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
