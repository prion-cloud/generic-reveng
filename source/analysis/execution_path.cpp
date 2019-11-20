#include <generic-reveng/analysis/execution_path.hpp>

namespace grev
{
    execution_path::execution_path(std::uint64_t const start_address) :
        start_jump_(emplace(start_address, nullptr).first),
        current_jump_(begin()) { }
    execution_path::~execution_path() = default;

    execution_path::execution_path(execution_path const& other) :
        std::unordered_map<z3_expression, z3_expression const*>(other),
        current_state_(other.current_state_),
        start_jump_(find(other.start_jump_->first)),
        current_jump_(find(other.current_jump_->first))
    {
        for (auto& [jump, succeeding_jump] : *this)
        {
            if (succeeding_jump == nullptr)
                continue;

            succeeding_jump = &find(*succeeding_jump)->first;
        }
    }
    execution_path::execution_path(execution_path&& other) noexcept = default;

    execution_path& execution_path::operator=(execution_path other) noexcept
    {
        swap(other);

        std::swap(current_state_, other.current_state_);

        std::swap(start_jump_, other.start_jump_);
        std::swap(current_jump_, other.current_jump_);

        return *this;
    }

    std::forward_list<execution_path> execution_path::update(machine_state_update const& update)
    {
        // TODO check for seal/current_address (?) -> support patching (?)

        if (current_jump_->second != nullptr)
        {
            // TODO Support loops with changing states

            seal();
            return { };
        }

        auto jumps = update.resolve(&current_state_);

        if (jumps.empty())
        {
            seal();
            return { };
        }

        auto current_jump = jumps.begin();

        std::forward_list<execution_path> new_paths;
        while (std::next(current_jump) != jumps.end())
        {
            auto& new_path = new_paths.emplace_front(*this);
            new_path.step(std::move(jumps.extract(current_jump++).value()));
        }

        step(std::move(jumps.extract(current_jump).value()));
        return new_paths;
    }

    std::optional<std::uint64_t> execution_path::current_address() const
    {
        if (current_jump_ == end())
            return std::nullopt;

        return current_jump_->first.evaluate();
    }

    // >>-----
    std::vector<std::uint64_t> execution_path::addresses() const
    {
        std::vector<std::uint64_t> addresses;
        std::unordered_set<std::uint64_t> address_register;

        for (auto it = start_jump_; it != current_jump_; it = find(*it->second))
        {
            auto const address = it->first.evaluate().value();

            if (address_register.contains(address))
                break;

            addresses.push_back(address);
            address_register.insert(address);
        }

        return addresses;
    }
    // -----<<

    void execution_path::seal()
    {
        // TODO Clear/optional current_state (?)

        current_jump_ = end();
    }
    void execution_path::step(z3_expression jump)
    {
        auto new_jump = try_emplace(std::move(jump)).first;

        current_jump_->second = &new_jump->first;
        current_jump_ = std::move(new_jump);
    }
}

static_assert(std::is_destructible_v<grev::execution_path>);

static_assert(std::is_copy_constructible_v<grev::execution_path>);
static_assert(std::is_nothrow_move_constructible_v<grev::execution_path>);

static_assert(std::is_copy_assignable_v<grev::execution_path>);
static_assert(std::is_nothrow_move_assignable_v<grev::execution_path>);
