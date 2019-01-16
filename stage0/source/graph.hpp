#pragma once

#include <map>
#include <unordered_set>

template <typename T, typename Comparator>
using graph = std::map<T, std::unordered_set<T const*>, Comparator>;
