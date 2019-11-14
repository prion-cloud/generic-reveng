#ifdef LINT
#include "reinterpret_copy.hpp"
#endif

namespace rev
{
    template <typename T, typename CharT, typename Traits>
    void reinterpret_copy(T* const destination, std::basic_string_view<CharT, Traits> const& source)
    {
        source.copy(
            // NOLINTNEXTLINE [cppcoreguidelines-pro-type-reinterpret-cast]
            reinterpret_cast<CharT*>(destination),
            sizeof(T));
    }
}
