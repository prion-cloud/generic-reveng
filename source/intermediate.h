#pragma once

#include <unordered_map>

#include "json.h"

class data_operator : json_serializable
{
    std::string value_;

public:

    data_operator();

    void deserialize(rapidjson::Value const& value) override;
    void serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const override;
};

class data_operand : json_serializable
{
    enum class type { imm, reg, var };

    type type_;
    int64_t value_;

public:

    data_operand();

    void deserialize(rapidjson::Value const& value) override;
    void serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const override;
};

class data_flow : json_serializable
{
    data_operator operator_;
    std::vector<data_operand> operands_;

public:

    data_flow();

    void deserialize(rapidjson::Value const& value) override;
    void serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const override;
};

class data_ir : json_serializable
{
    std::unordered_map<unsigned, std::vector<data_flow>> base_;

public:

    data_ir();

    void deserialize(rapidjson::Value const& value) override;
    void serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const override;

    std::vector<data_flow> const& operator[](unsigned instruction) const;
};
