#pragma once

#define CANCEL_IN '\n'

class console_printer
{
    std::vector<std::pair<const size_t, std::shared_ptr<const void>>> printed_;
    std::map<const size_t, const std::function<void(std::shared_ptr<const void>)>> print_funcs_;

    int16_t line0_;

public:

    explicit console_printer();

    TPL void register_func(std::function<void(T)> func);

    TPL void print(std::shared_ptr<T> object_ptr);
    void print_blank();

    void bottom_out(std::string message);
    std::string bottom_in(std::string prompt);

private:

    void print(size_t hash, std::shared_ptr<void> raw_object_ptr, std::function<void(std::shared_ptr<const void>)> raw_func);
    void reprint();

    std::string print_bottom(std::string text, bool await_input);
};

#include "console_printer_tpl.cpp"
