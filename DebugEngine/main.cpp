#include "stdafx.h"

#include "cli_debug.h"

#include "console.h"

#define COL_ERROR FOREGROUND_RED | FOREGROUND_INTENSITY

#define ARG_SUCCESS 0
#define ARG_FAILURE 1

#define FLAG_HELP "help"

#define FLAG_FAT "fat"
#define FLAG_HOT "hot"
#define FLAG_LAZY "lazy"
#define FLAG_UGLY "ugly"

static void print_help()
{
    std::ostringstream help;
    help << "This is kind of a reverse engineering tool, I guess." << std::endl << std::endl;
    std::left(help);
    help << "\t" << std::setw(20) << "--" FLAG_HELP << "Print this help." << std::endl << std::endl;
    help << "\t" << std::setw(20) << "--" FLAG_FAT << "Disable fatal errors." << std::endl;
    help << "\t" << std::setw(20) << "--" FLAG_HOT << "Enable instruction counting." << std::endl;
    help << "\t" << std::setw(20) << "--" FLAG_LAZY << "Do any memory allocation once it is needed." << std::endl;
    help << "\t" << std::setw(20) << "--" FLAG_UGLY << "Ignore instruction failures." << std::endl;

    std::cout << help.str();
}
static void print_manual()
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

    std::cout << manual.str();
}

static std::vector<uint8_t> dump_file(const std::string file_name)
{
    FILE* file;
    fopen_s(&file, file_name.c_str(), "rb");

    fseek(file, 0, SEEK_END);
    const auto length = ftell(file);
    rewind(file);

    const auto buffer = static_cast<char*>(malloc(length));
    fread(buffer, sizeof(char), length, file);
    fclose(file);

    const auto byte_vec = std::vector<uint8_t>(buffer, buffer + length);
    free(buffer);

    return byte_vec;
}

static int inspect_args(std::vector<std::string> args, std::string& file_name, flag_status& flag_status)
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
            
            if (flag == FLAG_FAT)
                flag_status.fat = false;
            else if (flag == FLAG_HOT)
                flag_status.hot = true;
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
    h_console = GetStdHandle(STD_OUTPUT_HANDLE);

    decolorize(std::cout);

    std::string file_name;
    const auto res = inspect_args(std::vector<std::string>(argv + 1, argv + argc), file_name, global_flags);
    if (res == ARG_FAILURE)
    {
        std::cerr << colorize(COL_ERROR) << "Invalid arguments." << decolorize << std::endl;
        return EXIT_FAILURE;
    }

    struct stat buf;
    if (stat(file_name.c_str(), &buf))
    {
        std::cerr << colorize(COL_ERROR) << "Specified file does not exist." << decolorize << std::endl;
        return EXIT_FAILURE;
    }

    char ext_c[_MAX_EXT];
    _splitpath_s(file_name.c_str(), nullptr, 0, nullptr, 0, nullptr, 0, ext_c, _MAX_EXT);

    std::string ext = ext_c;
    std::transform(ext.begin(), ext.end(), ext.begin(), tolower);

    std::unique_ptr<loader> loader;

    if (ext == ".exe")
    {
        loader = std::make_unique<loader_pe>();
    }
    else if (ext == ".aid")
    {
        loader = std::make_unique<loader_raw>();
    }
    else
    {
        std::cerr << colorize(COL_ERROR) << "Unknown file extension." << decolorize << std::endl;
        return EXIT_FAILURE;
    }

    try
    {
        if (!global_flags.lazy)
            std::cout << "Loading... ";

        const auto dbg = std::make_shared<debugger>(*loader, dump_file(file_name));

        std::cout << "File: \"" << file_name << "\"" << std::endl;

        std::cout << std::endl;

        print_manual();

        std::cin.get();
        system("cls");
        
        cli_debug cli_debug(dbg);

        for (char c = 0; c != 'x'; c = _getch())
        {
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
        std::cerr << std::endl << colorize(COL_ERROR) << err.what() << decolorize << std::endl;
        return EXIT_FAILURE;
    }
}
