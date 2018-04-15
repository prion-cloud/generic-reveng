#pragma once

/**
 * \brief Reads all bytes of a file.
 */
int create_filedump(std::string file_name, std::vector<char>& bytes);

/**
 * \brief Writes bytes to a file. If not existant, a new file is created.
 */
int create_dumpfile(std::string file_name, std::vector<char> bytes);
