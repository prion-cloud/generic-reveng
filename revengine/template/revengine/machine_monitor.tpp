#include <queue>

#ifdef LINT
#include <revengine/machine_monitor.hpp>
#endif

namespace rev
{
    template <typename Disassembler>
    machine_monitor<Disassembler>::machine_monitor(process const& process) :
        disass_(process.architecture())
    {
        std::queue<std::pair<std::uint64_t, execution_path&>> pending_forks;
        pending_forks.emplace(process.start_address(), paths_.emplace_front());
        do
        {
            auto const [address, path] = std::move(pending_forks.front());
            pending_forks.pop();

            for (auto fork = false; auto const& jump : inspect_block(process[address], &path))
            {
                if (auto const jump_value = jump.evaluate(); jump_value)
                    pending_forks.emplace(*jump_value, fork ? paths_.emplace_front(path) : path);

                fork = true;
            }
        }
        while (!pending_forks.empty());
    }

    template <typename Disassembler>
    std::forward_list<execution_path> const& machine_monitor<Disassembler>::paths() const
    {
        return paths_;
    }

    template <typename Disassembler>
    std::unordered_set<z3::expression>
        machine_monitor<Disassembler>::inspect_block(data_section data_section, execution_path* const path)
    {
        while (true)
        {
            if (data_section.data.empty())
                return { };

            auto const address = data_section.address;

            auto [impact, jumps] = disass_(&data_section, path->impact());
            path->update(address, std::move(impact));

            if (jumps)
                return std::move(*jumps);
        }
    }
}

#ifdef LINT
#include <revengine/reil_disassembler.hpp>
template class rev::machine_monitor<rev::dis::reil_disassembler>;
#endif
