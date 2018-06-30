#pragma once

class expr_tree_x86
{
    enum class op_un { neg };
    enum class op_bin { add, sub, mul, div };

    enum expr_type
    {
        t_const,
        t_reg,
        t_un,
        t_bin
    };

    expr_type type_;

    std::variant<int64_t, x86_reg, op_un, op_bin> value_;

    const expr_tree_x86* left_;
    const expr_tree_x86* right_;

public:

    explicit expr_tree_x86(int64_t value);
    explicit expr_tree_x86(x86_reg id);

    expr_tree_x86* add(const expr_tree_x86* other) const;

    std::string to_string() const;

    friend bool operator<(const expr_tree_x86& expr1, const expr_tree_x86& expr2);

private:

    expr_tree_x86(op_un op, const expr_tree_x86* next);
    expr_tree_x86(op_bin op, const expr_tree_x86* left, const expr_tree_x86* right);

    bool is_const() const;
    bool is_var() const;

    const std::map<op_un, char> map_un_
    {
        { op_un::neg, '-' }
    };
    const std::map<op_bin, char> map_bin_
    {
        { op_bin::add, '+' },
        { op_bin::sub, '-' },
        { op_bin::mul, '*' },
        { op_bin::div, '/' }
    };
};
