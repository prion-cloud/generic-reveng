#pragma once

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

struct json_serializable
{
    virtual ~json_serializable() = default;

    virtual void deserialize(rapidjson::Value const& value) = 0;
    virtual void serialize(rapidjson::Writer<rapidjson::StringBuffer>& writer) const = 0;
};
