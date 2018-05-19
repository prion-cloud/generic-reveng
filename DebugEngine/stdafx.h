#pragma once

#include <SDKDDKVer.h>

#include "../DebugEngine.Static/stdafx.h"

#include <conio.h>
#include <iomanip>
#include <iostream>
#include <functional>
#include <memory>
#include <typeinfo>

#define COL_DEF FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE

#define COL_FAIL FOREGROUND_RED | FOREGROUND_INTENSITY

#define COL_CALL FOREGROUND_GREEN | FOREGROUND_BLUE
#define COL_JUMP FOREGROUND_RED | FOREGROUND_GREEN
#define COL_LABEL FOREGROUND_GREEN
#define COL_REG FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY

#define COUT_COL(color, stream) \
    { \
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); \
        std::cout stream; \
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COL_DEF); \
    }

extern HANDLE h_console;
