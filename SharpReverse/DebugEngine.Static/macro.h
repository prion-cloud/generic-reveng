#pragma once

#define R_SUCCESS 0
#define R_FAILURE 1

#define THROW_E throw std::runtime_error("ERROR [" + std::string(__FILE__) + "/" + std::to_string(__LINE__) + "]")

#define E_ERR(cond) if (cond) return R_FAILURE
#define E_FAT(cond) if (cond) THROW_E
