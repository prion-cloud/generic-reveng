#include "stdafx.h"

#include "memory_monitor.h"

memory_monitor::memory_monitor()
    : access_count_(0) { }

void memory_monitor::inspect_access(const traceback_x86 traceback)
{
    uint64_t address;
    uint64_t value;

    if (traceback.memory_write(address, value))
        accesses_[address].push_back(access { access_count_++, true, value });

    if (traceback.memory_read(address, value))
        accesses_[address].push_back(access { access_count_++, false, value });
}
