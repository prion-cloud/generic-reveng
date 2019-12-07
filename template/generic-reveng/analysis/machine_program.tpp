#ifdef LINT
#include <generic-reveng/analysis/machine_program.hpp>
#endif

namespace grev
{
    template <typename Loader>
    machine_program machine_program::load(std::u8string data)
    {
        Loader const loader(data);

        machine_program program;

        program.data_ = std::move(data);

        program.architecture_ = loader.architecture();
        program.entry_point_address_ = loader.entry_point_address();

        program.memory_segments_ = loader.memory_segments();

        return program;
    }
}

#ifdef LINT
#include <generic-reveng/loading/pe_loader.hpp>
template grev::machine_program grev::machine_program::load<grev::pe_loader>(std::u8string);
#endif
