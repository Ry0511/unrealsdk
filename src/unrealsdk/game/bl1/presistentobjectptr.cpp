#include "unrealsdk/pch.h"

#include "unrealsdk/game/bl1/bl1.h"
#include "unrealsdk/version_error.h"

#if defined(UE3) && defined(ARCH_X86) && !defined(UNREALSDK_IMPORTING) \
    && defined(UNREALSDK_GAME_BL1)

namespace unrealsdk::game {

void BL1Hook::fsoftobjectptr_assign(unreal::FSoftObjectPtr* /* ptr */,
                                    const unreal::UObject* /* obj */) const {
    throw_version_error("Soft object pointers are not implemented in UE3");
}

void BL1Hook::flazyobjectptr_assign(unreal::FLazyObjectPtr* /* ptr */,
                                    const unreal::UObject* /* obj */) const {
    throw_version_error("Lazy object pointers are not implemented in UE3");
}

}  // namespace unrealsdk::game

#endif
