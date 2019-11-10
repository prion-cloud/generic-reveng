#include <queue>

#ifdef LINT
#include <revengine/machine_monitor.hpp>
#endif

namespace rev
{
    template <typename Disassembler>
    machine_monitor::machine_monitor(Disassembler const& disass, process const& process)
    {
        paths_.emplace_back();

        std::queue<std::pair<std::uint64_t, std::size_t>> pending_forks;
        pending_forks.emplace(process.start_address(), paths_.size() - 1);
        do
        {
            auto const [address, path_index] = std::move(pending_forks.front());
            pending_forks.pop();

            // TODO Loop detection

            auto data_section = process[address]; // TODO Cap and reuse (?)

            auto& path = paths_[path_index];

            std::optional<std::unordered_set<z3::expression, z3::expression::hash, z3::expression::equal_to>> jumps;
            do
            {
                if (data_section.data.empty())
                {
                    // TODO "Ran out of code"
                    jumps = { };
                    break;
                }

                path.step(data_section.address);

                jumps = disass(&data_section, &path.impact());
            }
            while (!jumps);

            if (jumps->empty())
            {
                // TODO "Interruption"
                continue;
            }

            for (auto fork = false; auto const& jump : *jumps)
            {
                std::size_t pending_path_index;
                if (fork)
                {
                    paths_.push_back(path);
                    pending_path_index = paths_.size() - 1;
                }
                else
                    pending_path_index = path_index;

                if (auto const jump_value = jump.evaluate(); jump_value)
                    pending_forks.emplace(*jump_value, pending_path_index);
                else
                {
                    // TODO "Ambiguous jump"
                }

                fork = true;
            }
        }
        while (!pending_forks.empty());
    }
}

#ifdef LINT
#include <revengine/reil_disassembler.hpp>
template rev::machine_monitor::machine_monitor(rev::dis::reil_disassembler const&, rev::process const&);
#endif
