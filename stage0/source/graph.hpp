#pragma once

#include <map>
#include <set>

template <typename T, typename Comparator>
class graph : public std::map<T, std::set<std::reference_wrapper<T const>, Comparator>, Comparator>
{
    using base = std::map<T, std::set<std::reference_wrapper<T const>, Comparator>, Comparator>;

public:

    using node = typename base::value_type;
};
