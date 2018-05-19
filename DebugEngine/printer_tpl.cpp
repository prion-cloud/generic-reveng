#include "stdafx.h"

TPL static size_t get_hash()
{
    return typeid(T).hash_code();
}

TPL void printer::register_func(std::function<void(T)> func)
{
    print_funcs_.emplace(get_hash<T>(),
        [func](const std::shared_ptr<const void> ptr) { func(*static_cast<const T*>(ptr.get())); });   
}

TPL void printer::print(const std::shared_ptr<T> object_ptr)
{
    print(get_hash<T>(), std::static_pointer_cast<void>(object_ptr), print_funcs_.at(get_hash<T>()));
}
