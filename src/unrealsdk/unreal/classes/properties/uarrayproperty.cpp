#include "unrealsdk/pch.h"

#include "unrealsdk/unreal/cast_prop.h"
#include "unrealsdk/unreal/classes/properties/uarrayproperty.h"
#include "unrealsdk/unreal/prop_traits.h"
#include "unrealsdk/unreal/structs/tarray.h"
#include "unrealsdk/unreal/structs/tarray_funcs.h"
#include "unrealsdk/unreal/wrappers/unreal_pointer.h"
#include "unrealsdk/unreal/wrappers/unreal_pointer_funcs.h"
#include "unrealsdk/unreal/wrappers/wrapped_array.h"

namespace unrealsdk::unreal {

UProperty* UArrayProperty::get_inner(void) const {
    return this->read_field(&UArrayProperty::Inner);
}

PropTraits<UArrayProperty>::Value PropTraits<UArrayProperty>::get(
    const UArrayProperty* prop,
    uintptr_t addr,
    const UnrealPointer<void>& parent) {
    auto inner = prop->get_inner();
    if (prop->ArrayDim > 1) {
        throw std::runtime_error(
            "Array has static array inner property - unsure how to handle, aborting!");
    }

    return {inner, reinterpret_cast<TArray<void>*>(addr), parent};
}

void PropTraits<UArrayProperty>::set(const UArrayProperty* prop,
                                     uintptr_t addr,
                                     const Value& value) {
    auto inner = prop->get_inner();
    if (prop->ArrayDim > 1) {
        throw std::runtime_error(
            "Array has static array inner property - unsure how to handle, aborting!");
    }
    if (value.type != inner) {
        throw std::runtime_error("Array does not contain fields of type "
                                 + (std::string)inner->Name);
    }

    cast_prop(inner, [prop, addr, &value]<typename T>(const T* inner) {
        auto arr = reinterpret_cast<TArray<void>*>(addr);

        auto new_size = value.size();
        auto current_size = arr->size();

        // If the new size is smaller, destroy anything dropping off the end
        for (size_t i = new_size; i < current_size; i++) {
            destroy_property<T>(inner, 0,
                                reinterpret_cast<uintptr_t>(arr->data) + (inner->ElementSize * i));
        }

        arr->resize(new_size, prop->ElementSize);

        for (size_t i = 0; i < new_size; i++) {
            set_property<T>(inner, 0,
                            reinterpret_cast<uintptr_t>(arr->data) + (inner->ElementSize * i),
                            value.get_at<T>(i));
        }
    });
}

void PropTraits<UArrayProperty>::destroy(const UArrayProperty* prop, uintptr_t addr) {
    auto inner = prop->get_inner();
    if (prop->ArrayDim > 1) {
        throw std::runtime_error(
            "Array has static array inner property - unsure how to handle, aborting!");
    }

    auto arr = reinterpret_cast<TArray<void>*>(addr);

    cast_prop(inner, [arr]<typename T>(const T* inner) {
        for (size_t i = 0; i < arr->size(); i++) {
            destroy_property<T>(inner, 0,
                                reinterpret_cast<uintptr_t>(arr->data) + (inner->ElementSize * i));
        }
    });

    if (arr->data != nullptr) {
        u_free(arr->data);
    }

    arr->data = nullptr;
    arr->count = 0;
    arr->max = 0;
}

}  // namespace unrealsdk::unreal
