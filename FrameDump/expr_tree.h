#pragma once

class expr_tree_x86
{
    struct node
    {
        virtual ~node() = default;
        virtual std::string to_string() const = 0;
        virtual bool is_const() const = 0;
        virtual node* neg() const = 0;
    };

    struct constant : node
    {
        int64_t value;
        explicit constant(int64_t value);
        std::string to_string() const override;
        bool is_const() const override;
        node* neg() const override;
    };
    struct variable : node
    {
        x86_reg id;
        bool negative;
        variable(x86_reg id, bool negative);
        std::string to_string() const override;
        bool is_const() const override;
        node* neg() const override;
    };

    struct table
    {
        std::vector<std::vector<const node*>> entries;
        std::string to_string() const;
        bool is_zero() const;
        bool is_one() const;
    };

    table numerator_;
    table denominator_;

public:

    const expr_tree_x86* neg() const;

    const expr_tree_x86* add(const expr_tree_x86* other) const;
    const expr_tree_x86* sub(const expr_tree_x86* other) const;
    const expr_tree_x86* mul(const expr_tree_x86* other) const;
    const expr_tree_x86* div(const expr_tree_x86* other) const;
    const expr_tree_x86* mod(const expr_tree_x86* other) const;

    std::string to_string() const;

    static const expr_tree_x86* make_const(int64_t value);
    static const expr_tree_x86* make_var(x86_reg id);

    friend bool operator<(const expr_tree_x86& expr1, const expr_tree_x86& expr2);

    friend table operator+(const table& table1, const table& table2);
    friend table operator*(const table& table1, const table& table2);

private:

    expr_tree_x86(table numerator, table denominator);
};
