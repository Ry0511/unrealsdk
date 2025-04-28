//
// Date       : 24/11/2024
// Project    : unrealsdk
// Author     : -Ry
//

#include "unrealsdk/game/bl1/bl1_config.h"
#include "unrealsdk/config.h"

namespace unrealsdk::game::bl1_cfg {

// ############################################################################//
//  | TOML DEF |
// ############################################################################//

namespace {
using TomlKeyType = std::string_view;
constexpr TomlKeyType CONSOLE_KEY = "unrealsdk.console_key";
constexpr TomlKeyType LOG_LOAD_PACKAGE = "unrealsdk.bl1.log_load_package";

}  // namespace

// ############################################################################//
//  | FUNCTION IMPLS |
// ############################################################################//

std::string console_key(void) {
    return std::string{config::get_str(CONSOLE_KEY).value_or("Tilde")};
}

bool is_log_load_package(void) {
    return config::get_bool(LOG_LOAD_PACKAGE).value_or(false);
}

}  // namespace unrealsdk::game::bl1_cfg