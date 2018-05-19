#pragma once

void replace(std::string text);
void erase(size_t size);

void set_cursor(int16_t line, int16_t column);
void set_cursor(std::pair<int16_t, int16_t> position);

CONSOLE_SCREEN_BUFFER_INFO get_buffer_info();

std::pair<int16_t, int16_t> get_cursor();

int16_t get_cursor_line();
int16_t get_cursor_column();
