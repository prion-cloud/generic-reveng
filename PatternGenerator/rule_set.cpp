#include "stdafx.h"

#include <cpprest/json.h>

#include "../Pretty/pretty.h"

#include "rule_set.h"

static web::json::value json_array(const std::vector<std::wstring>& vector)
{
    std::vector<web::json::value> json_array;
    json_array.reserve(vector.size());
    for (const auto& string : vector)
        json_array.push_back(web::json::value::string(string));
    return web::json::value::array(json_array);
}

void rule_set::add(const std::vector<std::wstring>& pattern, const std::vector<std::wstring>& replacement)
{
    entries_.push_back(entry { pattern, replacement });
}

void rule_set::json_serialize(std::wofstream& stream) const
{
    std::vector<web::json::value> json_entries;
    for (const auto& entry : entries_)
    {
        web::json::value value;
        value[U("pattern")] = json_array(entry.pattern);
        value[U("replacement")] = json_array(entry.replacement);

        json_entries.push_back(value);
    }

    stream << json_prettify(web::json::value::array(json_entries).serialize()) << std::endl;
}
