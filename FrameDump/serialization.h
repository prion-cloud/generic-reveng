#pragma once

TPL std::ofstream& operator<<=(std::ofstream& stream, const T& value);
TPL std::ofstream& operator<<=(std::ofstream& stream, const std::vector<T>& vector);

std::ofstream& operator<<=(std::ofstream& stream, const std::string& string);

TPL std::ifstream& operator>>=(std::ifstream& stream, T& value);
TPL std::ifstream& operator>>=(std::ifstream& stream, std::vector<T>& vector);

std::ifstream& operator>>=(std::ifstream& stream, std::string& string);

#include "serialization_tpl.cpp"
