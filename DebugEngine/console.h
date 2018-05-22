#pragma once

#define COL_DEF FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE
#define COL_FAIL FOREGROUND_RED | FOREGROUND_INTENSITY
#define COL_CALL FOREGROUND_GREEN | FOREGROUND_BLUE
#define COL_JUMP FOREGROUND_RED | FOREGROUND_GREEN
#define COL_LABEL FOREGROUND_GREEN
#define COL_REG FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY
#define COL_BREAK FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY | BACKGROUND_RED
#define COUT_COL(color, stream) \
    { \
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); \
        std::cout stream; \
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COL_DEF); \
    }

extern HANDLE h_console;

void replace(std::string text);
void erase(size_t size);

void set_cursor(int16_t line, int16_t column);
void set_cursor(std::pair<int16_t, int16_t> position);

CONSOLE_SCREEN_BUFFER_INFO get_buffer_info();

std::pair<int16_t, int16_t> get_cursor();

int16_t get_cursor_line();
int16_t get_cursor_column();
