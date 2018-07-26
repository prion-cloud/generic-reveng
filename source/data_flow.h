#pragma once

#include "../capstone/include/capstone.h"

#include <functional>
#include <string>
#include <vector>

class data_entry
{
    struct expr
    {
        std::string str;

        virtual ~expr() = default;
    };

    template <char C>
    struct expr_unop : expr
    {
        expr next;

        explicit expr_unop(const expr& next);
    };
    template <char C>
    struct expr_binop : expr
    {
        expr left;
        expr right;

        explicit expr_binop(const expr& left, const expr& right);
    };
    template <char C>
    struct expr_assop : expr
    {
        std::vector<expr> next;

        explicit expr_assop(const std::vector<expr>& next);
    };

    struct expr_reg : expr
    {
        x86_reg reg;

        explicit expr_reg(const x86_reg& reg);
    };
    struct expr_imm : expr
    {
        uint64_t imm;

        explicit expr_imm(const uint64_t& imm);
    };
    struct expr_mem : expr
    {
        expr mem;

        explicit expr_mem(const expr& mem);
    };
    struct expr_fp : expr
    {
        double fp;

        explicit expr_fp(const double& fp);
    };

    std::vector<expr> base_;

    std::string str_;

public:

    data_entry() = default;

    data_entry(const x86_reg& reg);
    data_entry(const uint64_t& imm);
    data_entry(const double& fp);

    const std::string& str() const;

    void concat(const data_entry& other);

    void memorize();

    void negate();
    void invert();

    void operator+=(const data_entry& other);
    void operator-=(const data_entry& other);
    void operator*=(const data_entry& other);
    void operator/=(const data_entry& other);
    void operator%=(const data_entry& other);

    void operator&=(const data_entry& other);
    void operator|=(const data_entry& other);
    void operator^=(const data_entry& other);

    void operator<<=(const data_entry& other);
    void operator>>=(const data_entry& other);

    bool operator==(const data_entry& other) const;

private:

    explicit data_entry(const std::vector<expr>& base);

    void update_str();

    void modify_all(const std::function<expr(expr)>& func);
    void modify_all(const std::function<expr(expr, expr)>& func, const data_entry& other);

    data_entry operator-() const;
};

class data_flow
{
    struct data_entry_hash
    {
        std::size_t operator()(const data_entry& k) const;
    };

    class data_map
    {
        std::unordered_map<data_entry, data_entry, data_entry_hash> base_;

    public:

        std::vector<std::string> str() const;

        data_entry effect(const x86_op_mem& mem, const bool& memorize);

        data_entry& operator[](const data_entry& container);
        data_entry& operator[](const cs_x86_op& operand);

        std::vector<std::pair<data_entry, data_entry>> operator*() const;
    };

    data_map map_;

public:

    data_flow() = default;

    std::vector<std::string> str() const;

    std::vector<std::pair<data_entry, data_entry>> status() const;

    void commit(const cs_insn& instruction);

private:

    // --- TODO: Convenience only

    static data_entry memorize(data_entry entry);

    friend data_entry operator/(data_entry first, const data_entry& second);
    friend data_entry operator%(data_entry first, const data_entry& second);

    // ---
};
