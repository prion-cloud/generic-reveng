#pragma once

#include "instruction.h"

class data_flow
{
    class expression
    {
        struct node
        {
            virtual ~node() = default;
            virtual std::string to_string() const = 0;
            virtual bool is_const(int64_t value) const;
            virtual std::optional<x86_reg> get_reg_value() const;
            virtual std::optional<int64_t> get_const_value() const;
            virtual std::optional<int64_t> get_add_value() const;
        };

        struct constant : node
        {
            int64_t value;
            explicit constant(int64_t value);
            std::string to_string() const override;
            bool is_const(int64_t value) const override;
            std::optional<int64_t> get_const_value() const override;
        };

        template <char C>
        struct op_assoc : node
        {
            std::vector<node*> next;
            explicit op_assoc(std::vector<node*> next, int64_t base,
                const std::function<int64_t(int64_t, int64_t)>& func);
            std::string to_string() const override;
        };

        struct op_add : op_assoc<'+'>
        {
            explicit op_add(const std::vector<node*>& next);
            std::optional<int64_t> get_add_value() const override;
        };
        struct op_mul : op_assoc<'*'>
        {
            explicit op_mul(const std::vector<node*>& next);
        };

        template <char C>
        struct op_unary : node
        {
            node* next;
            explicit op_unary(node* next);
            std::string to_string() const override;
        };

        template <char C>
        struct op : node
        {
            node* left;
            node* right;
            explicit op(node* left, node* right);
            std::string to_string() const override;
        };

        struct var_register : node
        {
            x86_reg id;
            explicit var_register(x86_reg id);
            std::string to_string() const override;
            std::optional<x86_reg> get_reg_value() const override;
        };
        struct var_memory : node
        {
            node* descriptor;
            explicit var_memory(node* descriptor);
            std::string to_string() const override;
        };

        node* root_;

    public:

        std::string to_string() const;
        
        std::optional<x86_reg> get_reg_value() const;
        std::optional<int64_t> get_const_value() const;
        std::optional<int64_t> get_add_value() const;

        expression memorize() const;

        static expression make_var(x86_reg id);
        static expression make_const(int64_t value);

        expression operator-() const;
        expression operator~() const;

        friend expression operator+(const expression& expr1, const expression& expr2);
        friend expression operator-(const expression& expr1, const expression& expr2);
        friend expression operator*(const expression& expr1, const expression& expr2);
        friend expression operator/(const expression& expr1, const expression& expr2);
        friend expression operator%(const expression& expr1, const expression& expr2);

        friend expression operator&(const expression& expr1, const expression& expr2);
        friend expression operator|(const expression& expr1, const expression& expr2);
        friend expression operator^(const expression& expr1, const expression& expr2);

        friend expression operator<<(const expression& expr1, const expression& expr2);
        friend expression operator>>(const expression& expr1, const expression& expr2);

    private:

        explicit expression(node* root);
    };

    class expression_variant
    {
        std::vector<expression> base_;

    public:

        expression_variant() = default;

        explicit expression_variant(expression expr);
        expression_variant(int64_t value);

        std::string to_string() const;

        void concat(const expression_variant& other);

        expression memorize() const;

        void negate();
        void invert();

        expression_variant& operator+=(const expression_variant& expr_var);
        expression_variant& operator-=(const expression_variant& expr_var);
        expression_variant& operator*=(const expression_variant& expr_var);
        expression_variant& operator/=(const expression_variant& expr_var);
        expression_variant& operator%=(const expression_variant& expr_var);

        expression_variant& operator&=(const expression_variant& expr_var);
        expression_variant& operator|=(const expression_variant& expr_var);
        expression_variant& operator^=(const expression_variant& expr_var);

        expression_variant& operator<<=(const expression_variant& expr_var);
        expression_variant& operator>>=(const expression_variant& expr_var);

        const std::vector<expression>& operator*() const;

    private:

        void transform(expression_variant other, const std::function<expression(expression, expression)>& function);
    };

    class expression_map
    {
        std::map<expression, expression_variant> base_;

    public:

        expression_map() = default;

        std::vector<std::string> to_string() const;

        expression_variant effect(x86_op_mem mem);

        expression_variant& operator[](const expression& expr);
        expression_variant& operator[](x86_reg id);
        expression_variant& operator[](instruction::operand operand);

        std::map<expression, expression_variant> const* operator->() const;
        const std::map<expression, expression_variant>& operator*() const;

    private:

        const std::map<x86_reg, std::pair<x86_reg, std::pair<uint64_t, unsigned>>> reg_map_
        {
            // RIP
            { X86_REG_IP,   { X86_REG_RIP, { UINT16_MAX, 0 } } },
            { X86_REG_EIP,  { X86_REG_RIP, { UINT32_MAX, 0 } } },

            // RAX
            { X86_REG_AL,   { X86_REG_RAX, {  UINT8_MAX, 0 } } },
            { X86_REG_AH,   { X86_REG_RAX, {  UINT8_MAX, 8 } } },
            { X86_REG_AX,   { X86_REG_RAX, { UINT16_MAX, 0 } } },
            { X86_REG_EAX,  { X86_REG_RAX, { UINT32_MAX, 0 } } },

            // RBX
            { X86_REG_BL,   { X86_REG_RBX, {  UINT8_MAX, 0 } } },
            { X86_REG_BH,   { X86_REG_RBX, {  UINT8_MAX, 8 } } },
            { X86_REG_BX,   { X86_REG_RBX, { UINT16_MAX, 0 } } },
            { X86_REG_EBX,  { X86_REG_RBX, { UINT32_MAX, 0 } } },

            // RCX
            { X86_REG_CL,   { X86_REG_RCX, {  UINT8_MAX, 0 } } },
            { X86_REG_CH,   { X86_REG_RCX, {  UINT8_MAX, 8 } } },
            { X86_REG_CX,   { X86_REG_RCX, { UINT16_MAX, 0 } } },
            { X86_REG_ECX,  { X86_REG_RCX, { UINT32_MAX, 0 } } },

            // RDX
            { X86_REG_DL,   { X86_REG_RDX, {  UINT8_MAX, 0 } } },
            { X86_REG_DH,   { X86_REG_RDX, {  UINT8_MAX, 8 } } },
            { X86_REG_DX,   { X86_REG_RDX, { UINT16_MAX, 0 } } },
            { X86_REG_EDX,  { X86_REG_RDX, { UINT32_MAX, 0 } } },

            // RSP
            { X86_REG_SPL,  { X86_REG_RSP, {  UINT8_MAX, 0 } } },
            { X86_REG_SP,   { X86_REG_RSP, { UINT16_MAX, 0 } } },
            { X86_REG_ESP,  { X86_REG_RSP, { UINT32_MAX, 0 } } },

            // RBP
            { X86_REG_BPL,  { X86_REG_RBP, {  UINT8_MAX, 0 } } },
            { X86_REG_BP,   { X86_REG_RBP, { UINT16_MAX, 0 } } },
            { X86_REG_EBP,  { X86_REG_RBP, { UINT32_MAX, 0 } } },

            // R8
            { X86_REG_R8B,  { X86_REG_R8,  {  UINT8_MAX, 0 } } },
            { X86_REG_R8W,  { X86_REG_R8,  { UINT16_MAX, 0 } } },
            { X86_REG_R8D,  { X86_REG_R8,  { UINT32_MAX, 0 } } },
            
            // R9
            { X86_REG_R9B,  { X86_REG_R9,  {  UINT8_MAX, 0 } } },
            { X86_REG_R9W,  { X86_REG_R9,  { UINT16_MAX, 0 } } },
            { X86_REG_R9D,  { X86_REG_R9,  { UINT32_MAX, 0 } } },
            
            // R10
            { X86_REG_R10B, { X86_REG_R10, {  UINT8_MAX, 0 } } },
            { X86_REG_R10W, { X86_REG_R10, { UINT16_MAX, 0 } } },
            { X86_REG_R10D, { X86_REG_R10, { UINT32_MAX, 0 } } },
            
            // R11
            { X86_REG_R11B, { X86_REG_R11, {  UINT8_MAX, 0 } } },
            { X86_REG_R11W, { X86_REG_R11, { UINT16_MAX, 0 } } },
            { X86_REG_R11D, { X86_REG_R11, { UINT32_MAX, 0 } } },
            
            // R12
            { X86_REG_R12B, { X86_REG_R12, {  UINT8_MAX, 0 } } },
            { X86_REG_R12W, { X86_REG_R12, { UINT16_MAX, 0 } } },
            { X86_REG_R12D, { X86_REG_R12, { UINT32_MAX, 0 } } },
            
            // R13
            { X86_REG_R13B, { X86_REG_R13, {  UINT8_MAX, 0 } } },
            { X86_REG_R13W, { X86_REG_R13, { UINT16_MAX, 0 } } },
            { X86_REG_R13D, { X86_REG_R13, { UINT32_MAX, 0 } } },
            
            // R14
            { X86_REG_R14B, { X86_REG_R14, {  UINT8_MAX, 0 } } },
            { X86_REG_R14W, { X86_REG_R14, { UINT16_MAX, 0 } } },
            { X86_REG_R14D, { X86_REG_R14, { UINT32_MAX, 0 } } },
            
            // R15
            { X86_REG_R15B, { X86_REG_R15, {  UINT8_MAX, 0 } } },
            { X86_REG_R15W, { X86_REG_R15, { UINT16_MAX, 0 } } },
            { X86_REG_R15D, { X86_REG_R15, { UINT32_MAX, 0 } } }
        };
    };

    expression_map map_;

    std::optional<instruction_sequence> sequence_;

public:

    data_flow() = default;
    explicit data_flow(const instruction& instruction);
    explicit data_flow(const instruction_sequence& instruction_sequence);

    std::vector<std::string> to_string() const;

    void apply(const instruction& instruction);

    bool empty() const;
    size_t size() const;

    std::vector<uint64_t> inspect_rip();

    std::vector<std::wstring> get_replacement() const;

    friend bool operator<(const data_flow& flow1, const data_flow& flow2);

private:

    friend bool operator<(const expression& expr1, const expression& expr2);

    friend expression operator+(const expression& expr1, const expression& expr2);
    friend expression operator-(const expression& expr1, const expression& expr2);
    friend expression operator*(const expression& expr1, const expression& expr2);
    friend expression operator/(const expression& expr1, const expression& expr2);
    friend expression operator%(const expression& expr1, const expression& expr2);

    friend expression operator&(const expression& expr1, const expression& expr2);
    friend expression operator|(const expression& expr1, const expression& expr2);
    friend expression operator^(const expression& expr1, const expression& expr2);

    friend expression operator<<(const expression& expr1, const expression& expr2);
    friend expression operator>>(const expression& expr1, const expression& expr2);

    friend expression_variant operator/(expression_variant expr_var1, const expression_variant& expr_var2);
    friend expression_variant operator%(expression_variant expr_var1, const expression_variant& expr_var2);
};
