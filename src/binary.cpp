#include <binary.hpp>

#include <algorithm>
#include <cassert>
#include <elf.h>
#include <fstream>
#include <variant>

[[nodiscard]] Binary Binary::fromFile(std::string_view filepath) {
    std::ifstream input(filepath.data(), std::ios::binary);
    if (!input) {
        throw std::runtime_error("Unable to read file");
    }
    std::vector<uint8_t> data(std::istreambuf_iterator<char>(input), {});
    return Binary(std::move(data));
}

bool checkMagicBytes(std::vector<uint8_t> &data) {
    std::vector<uint8_t> magic = {'\x7f', 'E', 'L', 'F'};
    for (size_t i = 0; i < 4; i++) {
        if (data[i] != magic[i]) {
            return false;
        }
    }
    return true;
}

template <typename T, std::input_iterator Input>
    requires(std::is_integral<T>::value)
void readIntRef(T &ref, Binary::ByteOrder byteOrder, Input &input) {
    uint64_t value = 0;
    size_t n = sizeof(T);
    switch (byteOrder) {
    case Binary::ByteOrder::Lsb:
        for (size_t i = 0; i < n; i++) {
            value |= ((uint64_t)(*input)) << (8 * i);
            input++;
        }
        break;
    case Binary::ByteOrder::Msb:
        for (size_t i = 0; i < n; i++) {
            value <<= 8;
            value |= *input;
            input++;
        }
        break;
    }
	ref = value;
}

[[nodiscard]] Binary::Binary(std::vector<uint8_t> &&data) : data_(data) {
    if (data_.size() < EI_NIDENT) {
        throw std::runtime_error("Truncated binary file");
    }
    if (!checkMagicBytes(data_)) {
        throw std::runtime_error("Invalid magic bytes");
    }

    if (data[4] == ELFCLASS32) {
        elfClass_ = ElfClass::Elf32;
    } else if (data[4] == ELFCLASS64) {
        elfClass_ = ElfClass::Elf64;
    } else {
        throw std::runtime_error("Invalid ELF class");
    }

    if (data[5] == ELFDATA2LSB) {
        byteOrder_ = ByteOrder::Lsb;
    } else if (data[5] == ELFDATA2MSB) {
        byteOrder_ = ByteOrder::Msb;
    } else {
        throw std::runtime_error("Invalid byte order");
    }

    {
        std::vector<uint8_t>::iterator iter = data_.begin() + EI_NIDENT;

        switch (elfClass_) {
        case ElfClass::Elf32:
            Elf32_Ehdr header32;
            std::copy(header32.e_ident, header32.e_ident + EI_NIDENT,
                      data_.begin());
            readIntRef(header32.e_type, byteOrder_, iter);
            readIntRef(header32.e_machine, byteOrder_, iter);
            readIntRef(header32.e_version, byteOrder_, iter);
            readIntRef(header32.e_entry, byteOrder_, iter);
            readIntRef(header32.e_phoff, byteOrder_, iter);
            readIntRef(header32.e_shoff, byteOrder_, iter);
            readIntRef(header32.e_flags, byteOrder_, iter);
            readIntRef(header32.e_ehsize, byteOrder_, iter);
            readIntRef(header32.e_phentsize, byteOrder_, iter);
            readIntRef(header32.e_phnum, byteOrder_, iter);
            readIntRef(header32.e_shentsize, byteOrder_, iter);
            readIntRef(header32.e_shnum, byteOrder_, iter);
            readIntRef(header32.e_shstrndx, byteOrder_, iter);
            header_ = header32;
            break;
        case ElfClass::Elf64:
            Elf64_Ehdr header64;
            std::copy(header64.e_ident, header64.e_ident + EI_NIDENT,
                      data_.begin());
            readIntRef(header64.e_type, byteOrder_, iter);
            readIntRef(header64.e_machine, byteOrder_, iter);
            readIntRef(header64.e_version, byteOrder_, iter);
            readIntRef(header64.e_entry, byteOrder_, iter);
            readIntRef(header64.e_phoff, byteOrder_, iter);
            readIntRef(header64.e_shoff, byteOrder_, iter);
            readIntRef(header64.e_flags, byteOrder_, iter);
            readIntRef(header64.e_ehsize, byteOrder_, iter);
            readIntRef(header64.e_phentsize, byteOrder_, iter);
            readIntRef(header64.e_phnum, byteOrder_, iter);
            readIntRef(header64.e_shentsize, byteOrder_, iter);
            readIntRef(header64.e_shnum, byteOrder_, iter);
            readIntRef(header64.e_shstrndx, byteOrder_, iter);
            header_ = header64;
            break;
        }
    }
}

[[nodiscard]] Binary::ElfClass Binary::getClass() const noexcept {
    return elfClass_;
}

[[nodiscard]] Binary::ByteOrder Binary::getByteOrder() const noexcept {
    return byteOrder_;
}

[[nodiscard]] Elf32_Ehdr Binary::getHeader32() const noexcept {
    assert(std::holds_alternative<Elf32_Ehdr>(header_));
    return std::get<Elf32_Ehdr>(header_);
}

[[nodiscard]] Elf64_Ehdr Binary::getHeader64() const noexcept {
    assert(std::holds_alternative<Elf64_Ehdr>(header_));
    return std::get<Elf64_Ehdr>(header_);
}
