#pragma once

TPL std::ofstream& operator<<=(std::ofstream& stream, const T& value);
TPL std::ofstream& operator<<=(std::ofstream& stream, const std::vector<T>& data);

TPL std::ifstream& operator>>=(std::ifstream& stream, T& value);
TPL std::ifstream& operator>>=(std::ifstream& stream, std::vector<T>& data);

#include "serialization_tpl.cpp"
