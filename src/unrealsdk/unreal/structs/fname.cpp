#include "unrealsdk/pch.h"

#include "unrealsdk/unreal/structs/fname.h"
#include "unrealsdk/unreal/wrappers/gnames.h"
#include "unrealsdk/unrealsdk.h"
#include "unrealsdk/utils.h"

namespace unrealsdk::unreal {

FName::FName(int32_t index, int32_t number) : index(index), number(number) {}

FName::FName(const wchar_t* name, int32_t number) {
    unrealsdk::internal::fname_init(this, name, number);
}
FName::FName(const std::string& name, int32_t number) : FName(utils::widen(name), number) {};
FName::FName(const std::wstring& name, int32_t number) {
    unrealsdk::internal::fname_init(this, name, number);
}

bool FName::operator==(const FName& other) const {
    return this->index == other.index && this->number == other.number;
}

bool FName::operator!=(const FName& other) const {
    return !operator==(other);
}

std::ostream& operator<<(std::ostream& stream, const FName& name) {
    auto entry = unrealsdk::gnames().at(name.index);

    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    if (entry->is_wide()) {
        stream << utils::narrow(entry->WideName);
    } else {
        stream << std::string_view{entry->AnsiName};
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)

    if (name.number != 0) {
        stream << '_' << std::to_string(name.number - 1);
    }
    return stream;
}

std::wostream& operator<<(std::wostream& stream, const FName& name) {
    auto entry = unrealsdk::gnames().at(name.index);

    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    if (entry->is_wide()) {
        stream << std::wstring_view{entry->WideName};
    } else {
        stream << utils::widen(entry->AnsiName);
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)

    if (name.number != 0) {
        stream << '_' << std::to_wstring(name.number - 1);
    }
    return stream;
}

FName::operator std::string() const {
    std::ostringstream stream;
    stream << *this;
    return stream.str();
}
FName::operator std::wstring() const {
    std::wostringstream stream;
    stream << *this;
    return stream.str();
}

FName operator""_fn(const wchar_t* str, size_t /*len*/) {
    return FName{str};
}

}  // namespace unrealsdk::unreal
