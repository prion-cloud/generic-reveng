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
                    // Workaround for jump = [REG] (TODO)
                    if (auto jump_reference = jump->reference())
                    {
                        path->state().resolve(&*jump_reference);
                        jump = jump_reference->dereference(jump->width());
                    }

                    auto const prev_jump = *jump;
                    memory_patch(jump->dependencies()).resolve(&*jump);
                    if (*jump != prev_jump)
                        path->patch_jump(*jump);

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

                execution update_execution;
                if (code.empty())
                {
                    execution const* import_execution;
                    if (auto const cached = import_cache_.find(*address); cached != import_cache_.end())
                    {
                        // Use cached entry
                        import_execution = &cached->second;
                    }
                    else if (auto const import = program_.load_imported(*address))
                    {
                        // Create new and cache
                        auto const cached = import_cache_.try_emplace(*address).first;
                        for (auto const& import_path : machine_monitor(disassembler, *import).execution_)
                            cached->second.push_front(import_path); // TODO move
                        import_execution = &cached->second;
                    }
                    else break; // TODO Do not rely on missing code for import call detection.

                    execution_state call_state;
                    for (auto const& current_state = path->state(); auto const& import_path : *import_execution)
                    {
                        auto const& import_state = import_path.state();

                        // TODO Use conditions
                        for (auto const& import_path_dependency : import_state.dependencies())
                            call_state.define(import_path_dependency, current_state[import_path_dependency]);
                    }

                    import_calls_[*address].push_front(call_state);

                    update_execution = std::move(*import_execution);
                }
                else
                {
                    // Disassemble next code
                    update_execution = disassembler(&*address, &code);
                }

                std::forward_list<execution_path> resolved_update_execution;
                for (auto& update_path : update_execution)
                {
                    if (auto const update_jump = update_path.jump())
                    {
                        auto resolved_update_jump = *update_jump;
                        path->state().resolve(&resolved_update_jump);
                        if (resolved_update_jump != update_jump)
                            update_path.patch_jump(std::move(resolved_update_jump));
                    }
                    else continue; // Prohibit loops (TODO)

                    path->state().resolve(&update_path.state());

                    memory_patch(update_path.state().dependencies()).resolve(&update_path.state());

                    path->state().resolve(&update_path.condition());

                    if (update_path.condition() == z3::expression::boolean_false())
                        continue;

                    resolved_update_execution.push_front(std::move(update_path));
                }

                if (resolved_update_execution.empty())
                    break;

                auto update_path = resolved_update_execution.begin();
                for (; std::next(update_path) != resolved_update_execution.end(); ++update_path)
                {
                    auto& next_path = execution_.emplace_front(*path);
                    pending_paths.push_front(&next_path);

                    next_path.condition() &= update_path->condition();
                    next_path.state() += update_path->state();
                    next_path.proceed(std::move(*update_path));
                }

                path->condition() &= update_path->condition();
                path->state() += update_path->state();
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
