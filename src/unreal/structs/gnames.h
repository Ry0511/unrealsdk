#ifndef UNREAL_STRUCTS_GNAMES_H
#define UNREAL_STRUCTS_GNAMES_H

namespace unrealsdk::unreal {

#if defined(_MSC_VER) && defined(ARCH_X86)
#pragma pack(push, 0x4)
#endif

struct FNameEntry {
    static constexpr auto NAME_SIZE = 1024;
    static constexpr auto NAME_WIDE_MASK = 0x1;
    static constexpr auto NAME_INDEX_SHIFT = 1;

    // NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,
    //             modernize-avoid-c-arrays,
    //             readability-identifier-naming)

#ifdef UE4
    int32_t Index;

   private:
    uint8_t UnknownData00[0x04];

   public:
    FNameEntry* HashNext;
#else
   private:
    uint8_t UnknownData00[0x08];

   public:
    int32_t Index;

   private:
    uint8_t UnknownData01[0x04];

   public:
#endif

    union {
        char AnsiName[NAME_SIZE];
        wchar_t WideName[NAME_SIZE];
    };

    // NOLINTEND(cppcoreguidelines-avoid-magic-numbers,
    //           modernize-avoid-c-arrays,
    //           readability-identifier-naming)

    /**
     * @brief Checks if this entry holds a wide string.
     *
     * @return True if this entry is wide, false if it's ANSI.
     */
    [[nodiscard]] bool is_wide(void) const;
};

#ifdef UE4

struct FChunkedFNameEntryArray {
    // NOLINTBEGIN(readability-identifier-naming)
    enum {
        NumElementsPerChunk = 0x4000,
        MaxChunkCount = 0x80,
        ChunkTableSize = (2 * 1024 * 1024 + NumElementsPerChunk - 1) / NumElementsPerChunk
    };

    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    FNameEntry** Objects[ChunkTableSize];
    int32_t Count;
    int32_t ChunksCount;
    // NOLINTEND(readability-identifier-naming)

    /**
     * @brief Get an element in the array, with bounds checking.
     *
     * @param idx The index to get.
     * @return The item at that index.
     */
    [[nodiscard]] FNameEntry* at(size_t idx) const;
};

#endif

#if defined(_MSC_VER) && defined(ARCH_X86)
#pragma pack(pop)
#endif

}  // namespace unrealsdk::unreal

#endif /* UNREAL_STRUCTS_GNAMES_H */
