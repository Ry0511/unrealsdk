# Changelog

## Upcoming

- Fixed that assigning an entire array, rather than getting the array and setting it's elements,
  would likely cause memory corruption. This was most common when using an array of large structs,
  and when assigning to one which was previously empty.

  [275bbc8b](https://github.com/bl-sdk/unrealsdk/commit/275bbc8b)

## 1.8.0

- Added support for sending property changed events, via `UObject::post_edit_change_property` and
  `UObject::post_edit_change_chain_property`.
  
  [a6040da4](https://github.com/bl-sdk/unrealsdk/commit/a6040da4)

- Made the error message when assigning incompatible array types more clear.

  See also https://github.com/bl-sdk/unrealsdk/issues/60 .

  [6222756c](https://github.com/bl-sdk/unrealsdk/commit/6222756c)

- Fixed checking the setting `exe_override` rather than the full `unrealsdk.exe_override`, like how
  it was documented / originally intended.

  [3010f486](https://github.com/bl-sdk/unrealsdk/commit/3010f486)

## 1.7.0

- `unrealsdk::unreal::cast` now copies the const-ness of its input object to its callbacks.

  [779d75ea](https://github.com/bl-sdk/unrealsdk/commit/779d75ea)

- Reworked `PropertyProxy` to be based on `UnrealPointer` (and reworked it too). This fixes some
  issues with ownership and possible use after frees.
  
  *This breaks binary compatibility*, though existing code should work pretty much as is after a
  recompile.
  
  [49bff4a4](https://github.com/bl-sdk/unrealsdk/commit/49bff4a4)

## v1.6.1

- Handled `UClass::Interfaces` also having a different offset between BL2 and TPS.

  [287c5802](https://github.com/bl-sdk/unrealsdk/commit/287c5802)

## v1.6.0

- Handled `UStruct` differing in size between BL2 and TPS.

  This affects all members on it's subclasses - `UClass::ClassDefaultObject`, `UClass::Interfaces`,
  `UFunction::FunctionFlags`, `UFunction::NumParams`, `UFunction::ParamsSize`,
  `UFunction::ReturnValueOffset`, and `UScriptStruct::StructFlags` have all now changed to methods
  which return a reference.

  [70854d65](https://github.com/bl-sdk/unrealsdk/commit/70854d65)

- Fixed all BL3 console output being treated as console commands instead.

  [1432408f](https://github.com/bl-sdk/unrealsdk/commit/1432408f)

## v1.5.0

- Completely reworked the configuration system.

  Environment variables and the `unrealsdk.env` are no longer used, due to issues with them not fully
  propagating within the same process. The new configuration now uses an `unrealsdk.toml` instead.
  
  Also added support for a user specific override file - `unrealsdk.user.toml`. This allows projects
  to ship their own `unrealsdk.toml`, without overwriting user's settings on update.

  [4daecbde](https://github.com/bl-sdk/unrealsdk/commit/4daecbde)

- `unrealsdk::hook_manager::inject_next_call` is now thread local.

  [427c8734](https://github.com/bl-sdk/unrealsdk/commit/427c8734)

- Fixed that `unrealsdk::commands::has_command` and `unrealsdk::commands::remove_command` were case
  sensitive, while `unrealsdk::commands::add_command` and the callbacks were not. Commands should be
  now be case insensitive everywhere.

  [b641706d](https://github.com/bl-sdk/unrealsdk/commit/b641706d)

- Fixed that the executed command message of custom sdk commands would not appear in console if you
  increased the minimum log level, and that they may have appeared out of order with respects to
  native engine messages.

  [b652da13](https://github.com/bl-sdk/unrealsdk/commit/b652da13)

- Added an additional console command hook in BL2, to cover commands not run directly via console.

  [1200fca4](https://github.com/bl-sdk/unrealsdk/commit/1200fca4)

- Renamed the `unrealsdk.locking_process_event` (previously `UNREALSDK_LOCKING_PROCESS_EVENT`)
  setting to `unrealsdk.locking_function_calls`, and expanded it's scope to cover all function
  calls. This fixes a few more possibilities for lockups.

  [bebaeab4](https://github.com/bl-sdk/unrealsdk/commit/bebaeab4)


- Trying to set a struct, array, or multicast delegate to itself is now a no-op, and prints a
  warning.

  [8a98db1f](https://github.com/bl-sdk/unrealsdk/commit/8a98db1f)

- The console key will now also be overwritten if it was previously set to `Undefine`.

  [631fa41e](https://github.com/bl-sdk/unrealsdk/commit/631fa41e)

## v1.4.0
- Fixed that UE3 `WeakPointer`s would always return null, due to an incorrect offset in the
  `UObject` header layout.

  [aca70889](https://github.com/bl-sdk/unrealsdk/commit/aca70889)

- Added support for Delegate and Multicast Delegate properties.

  [4e17d06d](https://github.com/bl-sdk/unrealsdk/commit/4e17d06d),
  [270ef4bf](https://github.com/bl-sdk/unrealsdk/commit/270ef4bf)

- Changed `unrealsdk::hook_manager::log_all_calls` to write to a dedicated file.

  [270ef4bf](https://github.com/bl-sdk/unrealsdk/commit/270ef4bf)

- Fixed missing all `CallFunction` based hooks in TPS - notably including the say bypass.

  [011fd8a2](https://github.com/bl-sdk/unrealsdk/commit/270ef4bf)

- Added the offline mode say crash fix for BL2+TPS as a base sdk hook.

  [2d9a36c7](https://github.com/bl-sdk/unrealsdk/commit/270ef4bf)


## v1.3.0
- Added a `WeakPointer` wrapper class with better ergonomics, including an emulated implementation
  when built under UE3.

  [fe3a9130](https://github.com/bl-sdk/unrealsdk/commit/fe3a9130)

- Added support for Soft Object, Soft Class, and Lazy Object Pointer properties.

  When accessing these via the standard getters/setters, they return their object reference
  directly. You can get the object identifier separately via `FSoftObjectPath::get_from` + related.

  [8f6fd71d](https://github.com/bl-sdk/unrealsdk/commit/8f6fd71d)

- Console commands bound via the sdk now appear in the sdk log file.

  [73ded7cb](https://github.com/bl-sdk/unrealsdk/commit/73ded7cb)

- Fixed that hooks could not always be removed after adding, or that they might not always fire.
  This could be caused by constructing `FName`s with strings which were *not* null terminated. The
  `FName` constructor no longer takes string views to avoid this, it needs explicitly strings.

  [227a93d2](https://github.com/bl-sdk/unrealsdk/commit/227a93d2)

- Moved several functions in the base `unrealsdk` namespace into `unrealsdk::internal`. These were
  all functions which relied on a game hook, but were primarily used to implement sdk internals, so
  shouldn't really have had reason to be called from user code. For example, `fname_init` is used
  to implement the `FName` constructor, so there's no reason for user code to call it directly.

  [73ded7cb](https://github.com/bl-sdk/unrealsdk/commit/73ded7cb)

- Added a dedicated `TArray<T>::free()` helper function, and inserted it where appropriate.

  [850763f9](https://github.com/bl-sdk/unrealsdk/commit/850763f9)

- Fixed an off by one in basically all array bounds checks.

  [001a87be](https://github.com/bl-sdk/unrealsdk/commit/001a87be)

## v1.2.0
- When an exception occurs during a hook, now mention what function it was under, to make debugging
  easier.

  [f2e21f60](https://github.com/bl-sdk/unrealsdk/commit/f2e21f60)

- Optimized performance of checking if to run hooks on functions which have none.

  [77bc3c54](https://github.com/bl-sdk/unrealsdk/commit/77bc3c54)

- Added support for `UByteAttributeProperty`, `UComponentProperty`, `UFloatAttributeProperty`,
  and `UIntAttributeProperty`.

  [45f07875](https://github.com/bl-sdk/unrealsdk/commit/45f07875),
  [adb5c986](https://github.com/bl-sdk/unrealsdk/commit/adb5c986)

- Added the `Enum` field to `UByteAttributeProperty`s.

  [fb9c043b](https://github.com/bl-sdk/unrealsdk/commit/fb9c043b)

- Added the `UNREALSDK_LOCKING_PROCESS_EVENT` env var, to help deal with games where it's not thread
  safe.

  **Note that this opens up the possibility for a deadlock in external code.**

  Both hooks and unreal function calls will attempt to acquire the "process event lock". It is
  possible to deadlock if a hook (which holds the process event lock) attempts to acquire another
  lock at the same time as the thread holding that lock tries to call an unreal function (which will
  attempt to acquire the process event lock).
  
  Swapped various unreal function calls with native equivalents to try reduce how many functions
  transitively have this behaviour - should only need to worry about calls to `BoundFunction::call`,
  or to `unrealsdk::process_event` directly.

  [35857adf](https://github.com/bl-sdk/unrealsdk/commit/35857adf),
  [b9469bbf](https://github.com/bl-sdk/unrealsdk/commit/b9469bbf),
  [d74ff4eb](https://github.com/bl-sdk/unrealsdk/commit/d74ff4eb),
  [91e3fcd5](https://github.com/bl-sdk/unrealsdk/commit/91e3fcd5)

- Fixed that a fully qualified `NamedObjectCache::find` would not allow subclasses. This was most
  notable with blueprint generated classes.

  [643fb46e](https://github.com/bl-sdk/unrealsdk/commit/643fb46e)

- Several logging module reworks. *This breaks binary compatibility*, though existing code should
  work pretty much as is after a recompile.

  - *Changed the semantics of `unrealsdk::logging::init`.* The `callbacks_only` arg was removed in
    favour of passing an empty path to disable file output, and disabling console output separately.
    The never version has the exact same signature, so existing code which used both args may need
    to be updated.

  - Changed the `location` arg to take a string view rather than a raw pointer.

  - Moved to a message queue model, where all printing is done in its own thread. This helps avoid
    deadlocks when using locking process event, should mean filesystem access doesn't block logic
    threads.

  - Fixed that empty log messages would not be properly shown in the unreal console.

  [02b56f18](https://github.com/bl-sdk/unrealsdk/commit/02b56f18),
  [91e3fcd5](https://github.com/bl-sdk/unrealsdk/commit/91e3fcd5),
  [8ec285fc](https://github.com/bl-sdk/unrealsdk/commit/8ec285fc)

- Tweaked `Pattern::sigscan` to more explicitly deal with sigscans failing. Existing code will have
  to be updated to either call `sigscan_nullable` (if failing is ok), or to pass a name to use in
  case of error (if throwing is ok).

  [7135bdf3](https://github.com/bl-sdk/unrealsdk/commit/7135bdf3),
  [b849b0e8](https://github.com/bl-sdk/unrealsdk/commit/91e3fcd5)

- Made the `UnrealPointer` constructor explicit.

  [26a47713](https://github.com/bl-sdk/unrealsdk/commit/26a47713)


## v1.1.0
- Changed a number of interfaces to take a string view rather than a const string reference.

  [5e59b16b..2c9f3082](https://github.com/bl-sdk/unrealsdk/compare/5e59b16b..2c9f3082)

- Changed `unrealsdk::init` to take a getter function which returns an abstract hook, rather than
  taking the hook itself. This allows the getter to be run "lazily", after logging is initialized.

  [8db5c52f](https://github.com/bl-sdk/unrealsdk/commit/8db5c52f)

- Fixed `UClass::implements` always returning false. This prevented setting interface properties.

  [18ccdd87](https://github.com/bl-sdk/unrealsdk/commit/18ccdd87)

- Added a `UStruct::superfields` iterator.

  [18ccdd87](https://github.com/bl-sdk/unrealsdk/commit/18ccdd87)

- When accessing a weak object pointer, also check the upper bound of it's object index. Previously,
  it may have been possible to dereference an object beyond the end of GObjects, this now returns
  `nullptr`.

  [38529ae8](https://github.com/bl-sdk/unrealsdk/commit/38529ae8)

- No longer conditionally compile `FText` only under UE4. It's now compiled in all versions, but
  throws versions errors when not available.

  [bbf94676](https://github.com/bl-sdk/unrealsdk/commit/bbf94676)

- Add `unrealsdk::load_package`.

  [70245fac](https://github.com/bl-sdk/unrealsdk/commit/70245fac)

- Make all iterators default-constructable, equivalent to their past-the-end iterators.

  [f09949a4](https://github.com/bl-sdk/unrealsdk/commit/f09949a4)

- Add support for building using standard GCC-based MinGW. This is not tested in CI however, as it
  requires a newer version than that available in Github Actions.

  [1729c749](https://github.com/bl-sdk/unrealsdk/commit/1729c749)

## v1.0.0
- Initial Release
