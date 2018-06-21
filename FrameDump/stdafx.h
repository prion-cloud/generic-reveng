#pragma once

#include <SDKDDKVer.h>

#ifdef _DEBUG
#undef _DEBUG
#define DEFINE_DEBUG
#endif

#pragma warning (disable : 5033)
#include "C:/Python27amd64/include/Python.h"

#ifdef DEFINE_DEBUG
#define _DEBUG
#endif

#include "../DebugEngine.Static/debugger.h"

#include <fstream>
#include <iomanip>
#include <iostream>
