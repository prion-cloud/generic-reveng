#include "stdafx.h"

#include "cli_debug.h"

#define ARG_SUCCESS 0
#define ARG_FAILURE 1

#define FLAG_HELP "help"

#define FLAG_NO_FAT "nofat"
#define FLAG_LAZY "lazy"
#define FLAG_UGLY "ugly"

void print_help()
{
    std::ostringstream help;
    help << "This is kind of a reverse engineering tool, I guess." << std::endl << std::endl;
    std::left(help);
    help << "\t" << std::setw(20) << "--" FLAG_HELP << "Print this help." << std::endl << std::endl;
    help << "\t" << std::setw(20) << "--" FLAG_NO_FAT << "Disable fatal errors." << std::endl;
    help << "\t" << std::setw(20) << "--" FLAG_LAZY << "Do any memory allocation once it is needed." << std::endl;
    help << "\t" << std::setw(20) << "--" FLAG_UGLY << "Ignore instruction failures." << std::endl;

    std::cout << help.str();
}
void print_manual()
{
    std::ostringstream manual;
    manual << std::string(68, '=') << std::endl;
    manual << "Press...";
    std::left(manual);
    manual << " " << std::setw(10) << "SPACE" << "to debug the next instruction" << std::endl;
    manual << "\t " << std::setw(10) << "ENTER" << "to execute a command" << std::endl;
    manual << "\t " << std::setw(10) << "r" << "to display recently accessed registers (* if any)" << std::endl;
    manual << "\t " << std::setw(10) << "b" << "to show an instruction's bytes" << std::endl;
    manual << "\t " << std::setw(10) << "x" << "to quit" << std::endl;
    manual << std::string(68, '=') << std::endl;
    manual << std::endl;

    std::cout << manual.str();
}

int inspect_args(std::vector<std::string> args, std::string& file_name, flag_status& flag_status)
{
    auto got_file_name = false;
    auto got_flag = false;

    for (const auto arg : args)
    {
        if (arg[0] == '-' && arg[1] == '-')
        {
            std::string flag = &arg[2];
            std::transform(flag.begin(), flag.end(), flag.begin(), tolower);

            if (flag == FLAG_HELP)
            {
                print_help();
                exit(EXIT_SUCCESS);
            }
            
            if (flag == FLAG_NO_FAT)
                flag_status.fat = false;
            else if (flag == FLAG_LAZY)
                flag_status.lazy = true;
            else if (flag == FLAG_UGLY)
                flag_status.ugly = true;
            else return ARG_FAILURE;

            std::cout << "Flag: " << flag << std::endl;
            got_flag = true;

            continue;
        }

        if (got_file_name)
            return ARG_FAILURE;

        file_name = arg;
        got_file_name = true;
    }

    if (!got_file_name)
        return ARG_FAILURE;

    if (!got_flag)
        std::cout << "No flags specified." << std::endl;

    std::cout << std::endl;

    return ARG_SUCCESS;
}

// Entry point
int main(const int argc, char* argv[])
{
    const auto h_console = GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(h_console, COL_DEF);

    std::string file_name;
    const auto res = inspect_args(std::vector<std::string>(argv + 1, argv + argc), file_name, global_flag_status);
    if (res == ARG_FAILURE)
    {
        COUT_COL(COL_FAIL, << "Invalid arguments.");
        exit(EXIT_FAILURE);
    }

    struct stat buf;
    if (stat(file_name.c_str(), &buf))
    {
        COUT_COL(COL_FAIL, << "Specified file does not exist.");
        exit(EXIT_FAILURE);
    }

    print_manual();

    try
    {
        cli_debug cli_debug(h_console, file_name);
        
        for (;;)
        {
            const char c = _getch();

            if (c == 'x')
                break;

            switch (c)
            {
            case ' ':
                cli_debug.step_into(false);
                break;
            case 'r':
                cli_debug.step_into(true);
                break;
            case '\r':
                cli_debug.process_command();
                break;
            case 'b':
                cli_debug.show_bytes();
                break;
            default:;
            }
        }
    }
    catch (std::runtime_error err)
    {
        COUT_COL(COL_FAIL, << err.what());
        exit(EXIT_FAILURE);
    }
}
