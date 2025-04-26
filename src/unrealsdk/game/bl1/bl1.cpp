#include "unrealsdk/pch.h"
#include "unrealsdk/game/bl1/bl1.h"

#include "unrealsdk/hook_manager.h"
#include "unrealsdk/memory.h"
#include "unrealsdk/unreal/structs/fframe.h"
#include "unrealsdk/version_error.h"

#if defined(UE3) && defined(ARCH_X86) && !defined(UNREALSDK_IMPORTING) \
    && defined(UNREALSDK_GAME_BL1)

using namespace unrealsdk::memory;
using namespace unrealsdk::unreal;

namespace unrealsdk::game {

void BL1Hook::hook(void) {
    hook_antidebug();

    hook_process_event();
    hook_call_function();

    // Grabbing these asap seems fine
    find_fname_init();
    find_fframe_step();
    find_construct_object();
    find_get_path_name();
    find_static_find_object();
    find_load_package();

    // idk if these are required or if they are correct
    hexedit_set_command();
    hexedit_array_limit();
    hexedit_array_limit_message();

    find_gobjects();
    find_gnames();
    find_gmalloc();
}

void BL1Hook::post_init(void) {
    LOG(MISC, "Attaching Hooks!");
    inject_console();
}

// ############################################################################//
//  | FFRAME STEP |
// ############################################################################//

namespace {

// - NOTE -
// This is inlined so we have to manually re-implement FFrame::Step using GNatives.
constexpr Pattern<36> FFRAME_STEP_SIG{
    "74 ??"              // je borderlands.59CEA4
    "8B45 D4"            // mov eax,dword ptr ss:[ebp-2C]
    "830D ???????? 02"   // or dword ptr ds:[1F73BE8],2
    "0FB610"             // movzx edx,byte ptr ds:[eax]
    "8B1495 {????????}"  // mov edx,dword ptr ds:[edx*4+1F97A80]
    "57"                 // push edi
    "8D4D BC"            // lea ecx,dword ptr ss:[ebp-44]
    "40"                 // inc eax
    "51"                 // push ecx
    "8B4D EC"            // mov ecx,dword ptr ss:[ebp-14]
    "8945 D4"            // mov dword ptr ss:[ebp-2C],eax
    "FFD2"               // call edx
};

// RET 0x8; Callee cleans up the stack (8 bytes)
// NOLINTNEXTLINE(modernize-use-using)
typedef void(__stdcall* fframe_step_func)(FFrame*, void*);
fframe_step_func** fframe_step_gnatives;

}  // namespace

void BL1Hook::find_fframe_step(void) {
    fframe_step_gnatives = FFRAME_STEP_SIG.sigscan_nullable<fframe_step_func**>();

    if (fframe_step_gnatives == nullptr) {
        LOG(ERROR, "FFrame::Step(...), GNatives was null.");
        return;
    }

    LOG(MISC, "FFrame::Step: {:p}", reinterpret_cast<void*>(fframe_step_gnatives));
}

void BL1Hook::fframe_step(FFrame* frame, UObject* /*obj*/, void* param) const {
    const uint8_t val = *frame->Code;
    frame->Code++;
    (*fframe_step_gnatives)[val](frame, param);
}

// ############################################################################//
//  | FNAME INIT |
// ############################################################################//

namespace {

constexpr Pattern<34> FNAME_INIT_SIG{
    "6A FF"            // push FFFFFFFF
    "68 ????????"      // push borderlands.18EB45B
    "64A1 00000000"    // mov eax,dword ptr fs:[0]
    "50"               // push eax
    "81EC 980C0000"    // sub esp,C98
    "A1 ????????"      // mov eax,dword ptr ds:[1F16980]
    "33C4"             // xor eax,esp
    "898424 940C0000"  // mov dword ptr ss:[esp+C94],eax
};

// NOLINTNEXTLINE(modernize-use-using)
typedef void(__thiscall* fname_init_func)(FName* name,
                                          const wchar_t* str,
                                          int32_t number,
                                          int32_t find_type,
                                          int32_t split_name);

fname_init_func fname_init_ptr = nullptr;

}  // namespace

void BL1Hook::find_fname_init(void) {
    fname_init_ptr = FNAME_INIT_SIG.sigscan_nullable<fname_init_func>();
    LOG(MISC, "FName::Init: {:p}", reinterpret_cast<void*>(fname_init_ptr));
}

void BL1Hook::fname_init(FName* name, const wchar_t* str, int32_t number) const {
    fname_init_ptr(name, str, number, 1, 1);
}

// ############################################################################//
//  | NOT IMPLEMENTED |
// ############################################################################//

void BL1Hook::ftext_as_culture_invariant(FText* /*text*/, TemporaryFString&& /*str*/) const {
    throw_version_error("FTexts are not implemented in UE3");
}

}  // namespace unrealsdk::game

#endif