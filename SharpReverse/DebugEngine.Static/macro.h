#pragma once

#define TPL template <typename T>

/**
 * \brief Indicator for a successful method execution
 */
#define R_SUCCESS 0
/**
 * \brief Indicator for a failed method execution
 */
#define R_FAILURE 1

/**
 * \brief Throw a runtime exception containing the file name and the code line.
 */
#define THROW_E throw std::runtime_error("ERROR [" + std::string(__FILE__) + ":" + std::to_string(__LINE__) + "]")

/**
 * \brief Non-fatal error; return as failure if condition is true.
 */
#define E_ERR(cond) if (cond) return R_FAILURE
/**
 * \brief Fatal error; throw exception if condition is true.
 */
#define E_FAT(cond) if (cond) THROW_E
