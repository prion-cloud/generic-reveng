#pragma once

// ReSharper disable CppUnusedIncludeDirective

#include <array>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "Windows.h"

#include "macro.h"

struct flag_status
{
    // Enable fatal errors.
    bool fat = true;
    // Do any memory allocation once it is needed. TODO: Not yet implemented.
    bool lazy = false;
    // TODO: Consider some utility.
    bool ugly = true;
};
extern flag_status global_flag_status;
