#include <generic-reveng/analysis/z3/context.hpp>

namespace grev::z3
{
    Z3_context const& context()
    {
        class configuration
        {
            Z3_config base_;

        public:

            configuration() :
                base_(Z3_mk_config()) { }
            ~configuration()
            {
                Z3_del_config(base_);
            }

            configuration(configuration const&) = delete;
            configuration(configuration&&) = delete;

            configuration& operator=(configuration const&) = delete;
            configuration& operator=(configuration&&) = delete;

            Z3_config const& base() const
            {
                return base_;
            }
        }
        static const configuration;

        class context
        {
            Z3_context base_;

        public:

            explicit context(Z3_config const& configuration)
            {
                base_ = Z3_mk_context_rc(configuration);
            }
            ~context()
            {
                Z3_del_context(base_);
            }

            context(context const&) = delete;
            context(context&&) = delete;

            context& operator=(context const&) = delete;
            context& operator=(context&&) = delete;

            Z3_context const& base() const
            {
                return base_;
            }
        }
        static const context(configuration.base());
        return context.base();
    }
}
