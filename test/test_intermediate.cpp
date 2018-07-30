#include "catch2/catch.hpp"
#include "helper.h"

#include "../source/intermediate.h"

#define TAG_INTERMEDIATE "[intermediate]"

TEST_CASE("Serialization", TAG_INTERMEDIATE)
{
    test_data<std::string, std::string> test_data;
    test_data.add(
        R"([{"instruction":8,"translation":[{"operator":"+=","operands":[{"type":"#","value":0},{"type":"#","value":1}]}]},)"
        R"({"instruction":315,"translation":[{"operator":"=][","operands":[{"type":"#","value":0},{"type":"#","value":1}]}]},)"
        R"({"instruction":486,"translation":[{"operator":"=-","operands":[{"type":"#","value":0},{"type":"#","value":0}]}]},)"
        R"({"instruction":580,"translation":[{"operator":"-=","operands":[{"type":"%","value":44},{"type":"$","value":8}]},{"operator":"[]=","operands":[{"type":"%","value":44},{"type":"#","value":0}]}]},)"
        R"({"instruction":442,"translation":[{"operator":"=","operands":[{"type":"#","value":0},{"type":"#","value":1}]}]}])");

    for (const auto&[in, out] : *test_data)
    {
        rapidjson::Document document;
        document.Parse(in.c_str(), in.size());

        REQUIRE_FALSE(document.HasParseError());

        data_ir ir;
        ir.deserialize(document);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

        ir.serialize(writer);

        REQUIRE(buffer.GetString() == out);
    }
}
