#include "intermediate.h"

#define JSON_INSTRUCTION "instruction"
#define JSON_TRANSLATION "translation"

#define JSON_OPERATOR "operator"
#define JSON_OPERANDS "operands"

#define JSON_TYPE "type"
#define JSON_VALUE "value"

#define JSON_TYPE_IMM '$'
#define JSON_TYPE_REG '%'
#define JSON_TYPE_VAR '#'

void data_operator::deserialize(rapidjson::Value const& value)
{
    value_ = value.GetString();
}
void data_operator::serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const
{
    writer.String(value_.c_str());
}

void data_operand::deserialize(rapidjson::Value const& value)
{
    auto const& json_type = value[JSON_TYPE];
    auto const& json_value = value[JSON_VALUE];

    switch (json_type.GetString()[0])
    {
    case JSON_TYPE_IMM:
        type_ = type::imm;
        break;
    case JSON_TYPE_REG:
        type_ = type::reg;
        break;
    case JSON_TYPE_VAR:
        type_ = type::var;
        break;
    default:
        throw std::runtime_error("JSON: Invalid operand specification");
    }

    value_ = json_value.GetInt64();
}
void data_operand::serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const
{
    writer.StartObject();

    writer.Key(JSON_TYPE);

    std::string json_type;
    switch (type_)
    {
    case type::imm:
        json_type = JSON_TYPE_IMM;
        break;
    case type::reg:
        json_type = JSON_TYPE_REG;
        break;
    case type::var:
        json_type = JSON_TYPE_VAR;
        break;
    }

    writer.String(json_type.c_str());

    writer.Key(JSON_VALUE);
    writer.Int64(value_);

    writer.EndObject();
}

void data_flow::deserialize(rapidjson::Value const& value)
{
    auto const& json_operator = value[JSON_OPERATOR];
    auto const& json_operands = value[JSON_OPERANDS];

    operator_.deserialize(json_operator);

    operands_ = std::vector<data_operand>(json_operands.Size());
    for (unsigned i = 0; i < operands_.size(); ++i)
        operands_.at(i).deserialize(json_operands[i]);
}
void data_flow::serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const
{
    writer.StartObject();

    writer.Key(JSON_OPERATOR);
    operator_.serialize(writer);

    writer.Key(JSON_OPERANDS);
    writer.StartArray();

    for (auto const& operand : operands_)
        operand.serialize(writer);

    writer.EndArray();

    writer.EndObject();
}

void data_ir::deserialize(rapidjson::Value const& value)
{
    for (unsigned i = 0; i < value.Size(); ++i)
    {
        auto const& json_instruction = value[i][JSON_INSTRUCTION];
        auto const& json_translation = value[i][JSON_TRANSLATION];

        std::vector<data_flow> translation(json_translation.Size());
        for (unsigned j = 0; j < translation.size(); ++j)
            translation.at(j).deserialize(json_translation[j]);

        base_.emplace(json_instruction.GetInt(), translation);
    }
}
void data_ir::serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const
{
    writer.StartArray();

    for (auto const&[instruction, translation] : base_)
    {
        writer.StartObject();

        writer.Key(JSON_INSTRUCTION);
        writer.Uint(instruction);

        writer.Key(JSON_TRANSLATION);
        writer.StartArray();

        for (auto const& flow : translation)
            flow.serialize(writer);

        writer.EndArray();

        writer.EndObject();
    }

    writer.EndArray();
}
