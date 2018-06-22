#pragma once

class memory_monitor
{
    struct access
    {
        size_t id;
        bool write;
        uint64_t value;
    };

    size_t access_count_;

    std::map<uint64_t, std::vector<access>> accesses_;

public:

    memory_monitor();

    void inspect_access(traceback_x86 traceback);
};
