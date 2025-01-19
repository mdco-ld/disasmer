#ifndef _BINARY_HPP_
#define _BINARY_HPP_

#include <cstdint>
#include <elf.h>
#include <string_view>
#include <variant>
#include <vector>

class Binary {
  public:
    [[nodiscard]] static Binary fromFile(std::string_view filepath);

    [[nodiscard]] Binary(std::vector<uint8_t> &&data);

    enum class ElfClass {
        Elf32,
        Elf64,
    };

    [[nodiscard]] ElfClass getClass() const noexcept;

    enum class ByteOrder {
        Lsb,
        Msb,
    };

    [[nodiscard]] ByteOrder getByteOrder() const noexcept;

	[[nodiscard]] Elf32_Ehdr getHeader32() const noexcept;
	[[nodiscard]] Elf64_Ehdr getHeader64() const noexcept;

  private:
    std::vector<uint8_t> data_;
    ElfClass elfClass_;
    ByteOrder byteOrder_;
	std::variant<Elf32_Ehdr, Elf64_Ehdr> header_;
};

#endif
