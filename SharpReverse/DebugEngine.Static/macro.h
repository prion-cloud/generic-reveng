#pragma once

#define F_SUCCESS 0
#define F_FAILURE 1

#define E_THROW throw std::runtime_error("ERROR [" + std::string(__FILE__) + "/" + std::to_string(__LINE__) + "]")

#define C_IMP(cond) if (cond) return F_FAILURE
#define C_VIT(cond) if (cond) E_THROW
