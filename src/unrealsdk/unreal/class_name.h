#ifndef UNREALSDK_UNREAL_CLASS_NAME_H
#define UNREALSDK_UNREAL_CLASS_NAME_H

#include "unrealsdk/unreal/classes/uclass.h"
#include "unrealsdk/unreal/classes/uobject.h"
#include "unrealsdk/unreal/prop_traits.h"
#include "unrealsdk/unreal/structs/fname.h"

namespace unrealsdk::unreal {

/**
 * @brief Gets the unreal class name of the templated type.
 *
 * @tparam T The type to get the name of.
 * @return The class' fname.
 */
template <typename T>
[[nodiscard]] FName cls_fname(void) {
    static FName name{0, 0};
    static bool initialized = false;

    if (!initialized) {
        name = FName{PropTraits<T>::CLASS};
        initialized = true;
    }

    return name;
}

template <>
[[nodiscard]] inline FName cls_fname<UClass>(void) {
    return L"Class"_fn;
}

/**
 * @brief Validates that an object is of the expected type.
 * @note Uses an exact type match, not if it's an instance.
 *
 * @tparam T Type type the object is expected to be.
 * @param obj Pointer to the object.
 * @return The object cast to the expected type.
 */
template <typename T>
T* validate_type(UObject* obj) {
    static const auto EXPECTED_CLS_NAME = cls_fname<T>();
    auto cls_name = obj->Class->Name;
    if (cls_name != EXPECTED_CLS_NAME) {
        throw std::invalid_argument("Property was of invalid type " + (std::string)cls_name);
    }
    return reinterpret_cast<T*>(obj);
}

}  // namespace unrealsdk::unreal

#endif /* UNREALSDK_UNREAL_CLASS_NAME_H */
