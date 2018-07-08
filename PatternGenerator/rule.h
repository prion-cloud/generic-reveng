#pragma once

struct deobfuscation_rule
{
    std::vector<std::string> pattern;
    std::vector<std::string> replacement;
};

class deobfuscation_rule_set
{
    std::vector<deobfuscation_rule> rules;

    std::vector<deobfuscation_rule> const* operator->() const;

public:

    void json_serialize(std::string file_name) const;
};
