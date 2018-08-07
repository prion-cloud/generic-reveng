#include "monitor.h"

value& monitor::data_map::operator[](value const& key)
{
    return base_[key];
}
value const& monitor::data_map::operator[](value const& key) const
{
    auto const it = base_.find(key);

    if (it == base_.end())
        return key;

    return it->second;
}

monitor::monitor(translator const& translator)
    : translator_(translator) { }

void monitor::commit(instruction const& instruction)
{
    for (auto const& [dest, src] : translator_[instruction])
        data_map_[dest] = data_map_[src];
}
