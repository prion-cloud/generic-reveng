#include "stdafx.h"

#include "printer.h"

#include "console.h"

static void update_cursor(const bool visible)
{
    CONSOLE_CURSOR_INFO info;
    GetConsoleCursorInfo(h_console, &info);
    info.bVisible = visible;
    SetConsoleCursorInfo(h_console, &info);
}

printer::printer()
{
    line0_ = get_cursor_line();

    update_cursor(false);
}

void printer::print_blank()
{
    print(-1, nullptr,
        [](std::shared_ptr<const void>) { std::cout << std::endl; });
}

void printer::bottom_out(const std::string message)
{
    print_bottom(message, false);
}
std::string printer::bottom_in(const std::string prompt)
{
    return print_bottom(prompt, true);
}

void printer::print(const size_t hash, const std::shared_ptr<void> raw_object_ptr, const std::function<void(std::shared_ptr<const void>)> raw_func)
{ 
    set_cursor(static_cast<int16_t>(printed_.size()) + line0_, 0); // TODO: Print max?

    raw_func(raw_object_ptr);
    printed_.push_back(std::make_pair(hash, raw_object_ptr));
}
void printer::reprint()
{
    const auto line = get_cursor_line() - line0_;

    if (line < 0 || line >= printed_.size())
        return;

    const auto print = printed_.at(line);

    if (print.second == nullptr)
        print_blank();
    else print_funcs_.at(print.first)(print.second);
}

std::string printer::print_bottom(const std::string text, const bool await_input)
{
    const auto buffer_info = get_buffer_info();

    set_cursor(buffer_info.srWindow.Bottom, 0);

    erase(buffer_info.srWindow.Right);

    std::cout << text;
    
    std::string input;
    if (await_input)
    {
        update_cursor(true);

        const char qualifier = std::cin.get();

        if (qualifier != CANCEL_IN)
        {
            std::getline(std::cin, input);
            input = qualifier + input;
        }
    }

    _getch();
    set_cursor(buffer_info.srWindow.Top, 0);

    if (await_input)
        update_cursor(false);
    
    set_cursor(buffer_info.srWindow.Bottom, 0);

    erase(text.size() + input.size());
    reprint();

    return input;
}
