#pragma once

class rule_set
{
    struct entry
    {
        std::vector<std::wstring> pattern;
        std::vector<std::wstring> replacement;
    };

    std::vector<entry> entries_;

public:

    rule_set() = default;

    void add(const std::vector<std::wstring>& pattern, const std::vector<std::wstring>& replacement);

    void json_serialize(std::wofstream& stream) const;
};
