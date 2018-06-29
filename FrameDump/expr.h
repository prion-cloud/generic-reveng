#pragma once

class expr
{
    class node
    {
    public:
        virtual ~node() = 0;
        virtual std::string evaluate() const = 0;
    };

    class op_unary : node
    {
        char op_;
        node* next_;
    public:
        op_unary(char op, node* next);
        std::string evaluate() const override;
    };
    class op_binary : node
    {
        char op_;
        node* left_;
        node* right_;
    public:
        op_binary(char op, node* left, node* right);
        std::string evaluate() const override;
    };

    class constant : node
    {
        int64_t value_;
    public:
        explicit constant(int64_t value);
        std::string evaluate() const override;
    };
    class variable : node
    {
        x86_reg id_;
    public:
        explicit variable(x86_reg id);
        std::string evaluate() const override;
    };

    node* root_ { };

public:

    expr() = default;

    std::string evaluate() const;

    expr wrap(char op) const;
    expr append(char op, expr other) const;

    static expr make_const(int64_t value);
    static expr make_var(x86_reg id);

private:

    explicit expr(node* root);
};
