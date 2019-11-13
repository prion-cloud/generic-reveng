#include "pe_optional_header.hpp"
#include "reinterpret_copy.hpp"

namespace rev::bin::pe
{
    pe_optional_header pe_optional_header::inspect_32(std::u8string_view* const data_view)
    {
        pe_optional_header optional_header { };

        constexpr std::size_t pos_base_address{4};
        std::uint32_t             base_address;
        reinterpret_copy(        &base_address,
            data_view->substr(pos_base_address));
        optional_header.          base_address =
                                  base_address;

        constexpr std::size_t         pos_import_address{80};
        reinterpret_copy(&optional_header.import_address,
                    data_view->substr(pos_import_address));

        constexpr std::size_t    size{224};
        data_view->remove_prefix(size);

        return optional_header;
    }
    pe_optional_header pe_optional_header::inspect_64(std::u8string_view* const data_view)
    {
        pe_optional_header optional_header { };

        constexpr std::size_t         pos_base_address{0};
        reinterpret_copy(&optional_header.base_address,
                    data_view->substr(pos_base_address));

        constexpr std::size_t         pos_import_address{96};
        reinterpret_copy(&optional_header.import_address,
                    data_view->substr(pos_import_address));

        constexpr std::size_t    size{240};
        data_view->remove_prefix(size);

        return optional_header;
    }
}
