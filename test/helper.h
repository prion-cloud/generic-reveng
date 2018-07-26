#pragma once

#include <vector>

template <typename In, typename Out>
class test_data
{
    std::vector<std::pair<In, Out>> base_;

public:

    test_data() = default;

    void add(In in, Out out)
    {
        base_.emplace_back(in, out);
    }

    const std::vector<std::pair<In, Out>>& operator*() const
    {
        return base_;
    }
};
