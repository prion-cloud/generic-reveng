#pragma once

#include <unordered_map>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

class data_operator
{
    std::string value_;

public:

    data_operator() = default;

    void deserialize(rapidjson::Value const& value);
    void serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const;
};

class data_operand
{
    enum class type { imm, reg, var };

    type type_;
    int64_t value_;

public:

    data_operand() = default;

    void deserialize(rapidjson::Value const& value);
    void serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const;
};

class data_flow
{
    data_operator operator_;
    std::vector<data_operand> operands_;

public:

    data_flow() = default;

    void deserialize(rapidjson::Value const& value);
    void serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const;
};

class data_ir
{
    std::unordered_map<unsigned, std::vector<data_flow>> base_;

public:

    data_ir() = default;

    void deserialize(rapidjson::Value const& value);
    void serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const;

    std::vector<data_flow> const& operator[](unsigned instruction) const;
};
