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

    template <char C>
    struct op : node
    {
        std::vector<const node*> next;
        explicit op(std::vector<const node*> next);
        std::string to_string() const override;
        bool is_const() const override;
        node* neg() const override;
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

    const node* root_;

    std::set<const void*> adds_;

public:

    const expr_tree_x86* neg() const;

    const expr_tree_x86* add(const expr_tree_x86* other) const;
    const expr_tree_x86* sub(const expr_tree_x86* other) const;

    std::string to_string() const;

    static const expr_tree_x86* make_const(int64_t value);
    static const expr_tree_x86* make_var(x86_reg id);

    friend bool operator<(const expr_tree_x86& expr1, const expr_tree_x86& expr2);

private:

    expr_tree_x86(const node* root, std::set<const void*> adds);
};
