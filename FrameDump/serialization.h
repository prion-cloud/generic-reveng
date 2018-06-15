#pragma once

TPL int serialize(std::string file_name, std::vector<T> data);
TPL int deserialize(std::string file_name, std::vector<T>& data);

#include "serialization_tpl.cpp"
