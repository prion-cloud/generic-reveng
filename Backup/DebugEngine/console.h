#pragma once

#define FOREGROUND_YELLOW FOREGROUND_RED | FOREGROUND_GREEN
#define FOREGROUND_MAGENTA FOREGROUND_RED | FOREGROUND_BLUE
#define FOREGROUND_CYAN FOREGROUND_GREEN | FOREGROUND_BLUE

#define FOREGROUND_WHITE FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE

#define BACKGROUND_YELLOW BACKGROUND_RED | BACKGROUND_GREEN
#define BACKGROUND_MAGENTA BACKGROUND_RED | BACKGROUND_BLUE
#define BACKGROUND_CYAN BACKGROUND_GREEN | BACKGROUND_BLUE

#define BACKGROUND_WHITE BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE

extern HANDLE h_console;

void replace(std::string text);
void erase(size_t size);

void set_cursor(int16_t line, int16_t column);
void set_cursor(std::pair<int16_t, int16_t> position);

CONSOLE_SCREEN_BUFFER_INFO get_buffer_info();

std::pair<int16_t, int16_t> get_cursor();

int16_t get_cursor_line();
int16_t get_cursor_column();

class colorize
{
    uint16_t color_;

public:

    explicit colorize(uint16_t color);

    std::ostream& operator()(std::ostream& stream) const;
};

std::ostream& operator<<(std::ostream& stream, colorize colorize);

std::ostream& decolorize(std::ostream& stream);
