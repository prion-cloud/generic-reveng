#pragma once

#define F_SUCCESS 0
#define F_FAILURE 1

#define E_THROW throw std::runtime_error("ERROR [" + std::string(__FILE__) + "/" + std::to_string(__LINE__) + "]")

#define C_ERR(cond) if (cond) return F_FAILURE
#define C_FAT(cond) if (cond) E_THROW
