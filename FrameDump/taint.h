#pragma once

#include <functional>

#include "instruction.h"

/*
enum class loc_type { err, reg, mem };
struct var_loc
{
    loc_type type;
    uint64_t value;

    var_loc();
    explicit var_loc(loc_type type, uint64_t value);

    friend bool operator<(const var_loc& loc1, const var_loc& loc2);
};
*/

enum class code_constraint_type
{
    none = -1,
    for_all,
    exact
};
struct code_constraint
{
    code_constraint_type type;

    uint64_t id;
    int64_t value;

    code_constraint(code_constraint_type type, uint64_t id, int64_t value);

    static code_constraint none();
};

class var_expr
{
    class node
    {
    public:
        virtual ~node() = default;
        virtual int64_t evaluate() const = 0;
    };

    class operand_un : public node
    {
        std::shared_ptr<node> next_;
        std::function<int64_t(int64_t)> function_;
    public:
        explicit operand_un(std::shared_ptr<node> next, std::function<int64_t(int64_t)> function);
        int64_t evaluate() const override;
    };
    class operand_bin : public node
    {
        std::shared_ptr<node> left_;
        std::shared_ptr<node> right_;
        std::function<int64_t(int64_t, int64_t)> function_;
    public:
        explicit operand_bin(std::shared_ptr<node> left, std::shared_ptr<node> right, std::function<int64_t(int64_t, int64_t)> function);
        int64_t evaluate() const override;
    };

    class constant : public node
    {
        operand_x86 source_;
    public:
        explicit constant(operand_x86 source);
        int64_t evaluate() const override;
    };

    std::shared_ptr<node> root_;

public:

    var_expr();
    explicit var_expr(operand_x86 root_source);

    int64_t evaluate() const;

    void neg();

    void add(var_expr expression);
    void sub(var_expr expression);

    void mul(var_expr expression);
    void div(var_expr expression);
};
