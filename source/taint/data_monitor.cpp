#include "data_monitor.h"

data_value* taint::data_monitor::data_map::operator[](data_value const& key)
{
    // TODO

    return &base_.at(key);
}
std::vector<data_value*> taint::data_monitor::data_map::operator[](std::vector<data_value> const& keys)
{
    std::vector<data_value*> result;
    for (auto const& key : keys)
        result.push_back(operator[](key));

    return result;
}

taint::data_monitor::data_monitor(ir const& ir)
    : ir_(ir) { }

void taint::data_monitor::commit(instruction const& instruction)
{
    for (auto const& abstr : ir_[instruction.id])
    {
        auto const& cont = abstr.make_contextual(instruction.operands);

        *data_map_[cont.destination] = cont.operation(data_map_[cont.sources]);
    }
}
