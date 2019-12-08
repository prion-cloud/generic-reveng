#include <generic-reveng/analysis/execution_path.hpp>

namespace grev
{
    execution_path::execution_path(z3::expression initial_jump) :
        initial_jump_(try_emplace(std::move(initial_jump)).first),
        condition_(z3::expression::boolean_true()),
        jump_(begin()) { }
    execution_path::~execution_path() = default;

    execution_path::execution_path(execution_path const& other) :
        std::unordered_map<z3::expression, z3::expression const*>(other),
        initial_jump_(find(other.initial_jump_->first)),
        condition_(other.condition_),
        state_(other.state_),
        jump_(find(other.jump_->first))
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

        std::swap(initial_jump_, other.initial_jump_);

        std::swap(condition_, other.condition_);
        std::swap(state_, other.state_);
        std::swap(jump_, other.jump_);

        return *this;
    }

    z3::expression& execution_path::condition()
    {
        return condition_;
    }
    z3::expression const& execution_path::condition() const
    {
        return condition_;
    }

    execution_state& execution_path::state()
    {
        return state_;
    }
    execution_state const& execution_path::state() const
    {
        return state_;
    }

    void execution_path::proceed(z3::expression jump)
    {
        state_.resolve(&jump);

        auto new_jump = try_emplace(std::move(jump)).first;

        jump_->second = &new_jump->first;
        jump_ = std::move(new_jump);
    }
    void execution_path::proceed(execution_path update_path)
    {
        for (auto jump = update_path.initial_jump_;; jump = update_path.find(*jump->second))
        {
            if (auto const* const next_jump = jump->second)
                proceed(*next_jump);

            if (jump == update_path.jump_)
                break;
        }

        condition_ &= update_path.condition_;
        state_ += std::move(update_path.state_);
    }

    std::optional<z3::expression> execution_path::jump() const
    {
        if (jump_->second != nullptr) // TODO Support loops with changing states
            return std::nullopt;

        return jump_->first;
    }

    // >>-----
    std::vector<std::uint32_t> execution_path::addresses() const
    {
        std::vector<std::uint32_t> addresses;
        for (auto jump = initial_jump_;; jump = find(*jump->second))
        {
            if (auto const address = jump->first.evaluate())
                addresses.push_back(*address);
            else
                break;

            if (jump == jump_ || jump->second == nullptr)
                break;
        }

        return addresses;
    }
    // -----<<
}

static_assert(std::is_destructible_v<grev::execution_path>);

static_assert(std::is_copy_constructible_v<grev::execution_path>);
static_assert(std::is_nothrow_move_constructible_v<grev::execution_path>);

static_assert(std::is_copy_assignable_v<grev::execution_path>);
static_assert(std::is_nothrow_move_assignable_v<grev::execution_path>);
