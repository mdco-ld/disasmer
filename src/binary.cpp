#include <binary.hpp>

#include <cassert>
#include <elf.h>
#include <fstream>
#include <iostream>
#include <print>

namespace binary {

bool checkMagicBytes(std::vector<uint8_t> &data, Binary::Type type) {
    switch (type) {
    case Binary::Type::Elf32:
    case Binary::Type::Elf64:
        std::vector<uint8_t> magic = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
        if (data.size() < 4) {
            return false;
        }
        for (size_t i = 0; i < 4; i++) {
            if (data[i] != magic[i]) {
                return false;
            }
        }
        return true;
    }
    return false;
}

Binary::Type identifyFileType(std::vector<uint8_t> &data) {
    if (checkMagicBytes(data, Binary::Type::Elf32)) {
        if (data[EI_CLASS] == ELFCLASS32) {
            return Binary::Type::Elf32;
        } else if (data[EI_CLASS] == ELFCLASS64) {
            return Binary::Type::Elf64;
        } else {
            throw std::runtime_error("Invalid ELF class");
        }
    }
    throw std::runtime_error("Unrecognized binary type");
}

[[nodiscard]] std::unique_ptr<Binary> fromFile(std::string_view filepath) {
    std::ifstream input(filepath.data(), std::ios::binary);
    if (!input) {
        throw std::runtime_error("Unable to read file");
    }
    std::vector<uint8_t> data(std::istreambuf_iterator<char>(input), {});
    Binary::Type type = identifyFileType(data);
    switch (type) {
    case Binary::Type::Elf32:
        return std::make_unique<Elf32>(std::move(data));
    case Binary::Type::Elf64:
        return std::make_unique<Elf64>(std::move(data));
    }

    const bool unreachable = false;
    assert(unreachable);
}

size_t Binary::readIntRef(uint8_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(uint8_t), data_);
    return position + sizeof(uint8_t);
}
size_t Binary::readIntRef(uint16_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(uint16_t), data_);
    return position + sizeof(uint16_t);
}
size_t Binary::readIntRef(uint32_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(uint32_t), data_);
    return position + sizeof(uint32_t);
}
size_t Binary::readIntRef(uint64_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(uint64_t), data_);
    return position + sizeof(uint64_t);
}
size_t Binary::readIntRef(int8_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(int8_t), data_);
    return position + sizeof(int8_t);
}
size_t Binary::readIntRef(int16_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(int16_t), data_);
    return position + sizeof(int16_t);
}
size_t Binary::readIntRef(int32_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(int32_t), data_);
    return position + sizeof(int32_t);
}
size_t Binary::readIntRef(int64_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(int64_t), data_);
    return position + sizeof(int64_t);
}

uint64_t readLsb(size_t position, size_t intSize,
                 const std::vector<uint8_t> &data) {
    uint64_t ret = 0;
    for (size_t i = 0; i < intSize; i++) {
        ret |= data[position + i] << (8 * i);
    }
    return ret;
}

uint64_t readMsb(size_t position, size_t intSize,
                 const std::vector<uint8_t> &data) {
    uint64_t ret = 0;
    for (size_t i = 0; i < intSize; i++) {
        ret <<= 8;
        ret |= data[position + i];
    }
    return ret;
}

std::function<uint64_t(size_t, size_t, const std::vector<uint8_t> &)>
getElfReaderFunction(const std::vector<uint8_t> &data) {
    if (data[EI_DATA] == ELFDATA2LSB) {
        return readLsb;
    }
    if (data[EI_DATA] == ELFDATA2MSB) {
        return readMsb;
    }
    throw std::runtime_error("Invalid data encoding");
}

std::map<size_t, std::string> readElfStringTable(Binary *bin, size_t offset,
                                                 size_t size) {
    std::map<size_t, std::string> ret;
    size_t position = offset;
    int8_t c;
    std::string current;
    while (position < offset + size) {
        position = bin->readIntRef(c, position);
        if (c) {
            current += c;
        } else {
            ret.insert({position - current.size() - offset - 1, current});
            std::println("string offset = {}, string = {}",
                         position - current.size() - offset - 1, current);
            current.clear();
        }
    }
    return ret;
}

Elf32::Elf32(std::vector<std::uint8_t> &&data)
    : Binary(Type::Elf32, std::forward<std::vector<uint8_t>>(data),
             getElfReaderFunction(data)) {

    std::copy(header_.e_ident, header_.e_ident + EI_NIDENT, getData().begin());
    size_t position = EI_NIDENT;
    position = readIntRef(header_.e_type, position);
    position = readIntRef(header_.e_machine, position);
    position = readIntRef(header_.e_version, position);
    position = readIntRef(header_.e_entry, position);
    position = readIntRef(header_.e_phoff, position);
    position = readIntRef(header_.e_shoff, position);
    position = readIntRef(header_.e_flags, position);
    position = readIntRef(header_.e_ehsize, position);
    position = readIntRef(header_.e_phentsize, position);
    position = readIntRef(header_.e_phnum, position);
    position = readIntRef(header_.e_shentsize, position);
    position = readIntRef(header_.e_shnum, position);
    position = readIntRef(header_.e_shstrndx, position);

    sectionHeaders_.resize(header_.e_shnum);
    position = header_.e_shoff;
    for (size_t i = 0; i < header_.e_shnum; i++) {
        position = readIntRef(sectionHeaders_[i].sh_name, position);
        position = readIntRef(sectionHeaders_[i].sh_type, position);
        position = readIntRef(sectionHeaders_[i].sh_flags, position);
        position = readIntRef(sectionHeaders_[i].sh_addr, position);
        position = readIntRef(sectionHeaders_[i].sh_offset, position);
        position = readIntRef(sectionHeaders_[i].sh_size, position);
        position = readIntRef(sectionHeaders_[i].sh_link, position);
        position = readIntRef(sectionHeaders_[i].sh_info, position);
        position = readIntRef(sectionHeaders_[i].sh_addralign, position);
        position = readIntRef(sectionHeaders_[i].sh_entsize, position);
    }
    sectionsStringTable_ =
        readElfStringTable(this, sectionHeaders_[header_.e_shstrndx].sh_offset,
                           sectionHeaders_[header_.e_shstrndx].sh_size);
}

Elf64::Elf64(std::vector<std::uint8_t> &&data)
    : Binary(Type::Elf64, std::forward<std::vector<uint8_t>>(data),
             getElfReaderFunction(data)) {

    std::copy(header_.e_ident, header_.e_ident + EI_NIDENT, getData().begin());
    size_t position = EI_NIDENT;
    position = readIntRef(header_.e_type, position);
    position = readIntRef(header_.e_machine, position);
    position = readIntRef(header_.e_version, position);
    position = readIntRef(header_.e_entry, position);
    position = readIntRef(header_.e_phoff, position);
    position = readIntRef(header_.e_shoff, position);
    position = readIntRef(header_.e_flags, position);
    position = readIntRef(header_.e_ehsize, position);
    position = readIntRef(header_.e_phentsize, position);
    position = readIntRef(header_.e_phnum, position);
    position = readIntRef(header_.e_shentsize, position);
    position = readIntRef(header_.e_shnum, position);
    position = readIntRef(header_.e_shstrndx, position);

    std::println("section header entity size = {}", header_.e_shentsize);

    sectionHeaders_.resize(header_.e_shnum);
    position = header_.e_shoff;
    for (size_t i = 0; i < header_.e_shnum; i++) {
        position = readIntRef(sectionHeaders_[i].sh_name, position);
        position = readIntRef(sectionHeaders_[i].sh_type, position);
        position = readIntRef(sectionHeaders_[i].sh_flags, position);
        position = readIntRef(sectionHeaders_[i].sh_addr, position);
        position = readIntRef(sectionHeaders_[i].sh_offset, position);
        position = readIntRef(sectionHeaders_[i].sh_size, position);
        position = readIntRef(sectionHeaders_[i].sh_link, position);
        position = readIntRef(sectionHeaders_[i].sh_info, position);
        position = readIntRef(sectionHeaders_[i].sh_addralign, position);
        position = readIntRef(sectionHeaders_[i].sh_entsize, position);
    }
    sectionsStringTable_ =
        readElfStringTable(this, sectionHeaders_[header_.e_shstrndx].sh_offset,
                           sectionHeaders_[header_.e_shstrndx].sh_size);
}

std::vector<uint8_t> &Binary::getData() noexcept { return data_; }

Binary::Binary(Type type, std::vector<uint8_t> &&data, ReaderFn reader)
    : type_(type), data_(data), reader_(reader) {}

[[nodiscard]] Elf32_Ehdr Elf32::getHeader() const noexcept { return header_; }

[[nodiscard]] Elf64_Ehdr Elf64::getHeader() const noexcept { return header_; }

[[nodiscard]] Elf32_Shdr Elf32::getSectionHeader(size_t idx) const noexcept {
    return sectionHeaders_[idx];
}

[[nodiscard]] Elf64_Shdr Elf64::getSectionHeader(size_t idx) const noexcept {
    return sectionHeaders_[idx];
}

[[nodiscard]] const std::string_view Elf32::getSectionName(size_t idx) const {
    if (idx >= header_.e_shnum) {
        throw std::runtime_error("Section header index out of bounds");
    }
    auto sectionHeader = sectionHeaders_[idx];
    auto it = sectionsStringTable_.find(sectionHeader.sh_name);
    if (it == sectionsStringTable_.end()) {
        throw std::runtime_error("Invalid offset for section name");
    }
    return it->second;
}

[[nodiscard]] const std::string_view Elf64::getSectionName(size_t idx) const {
    if (idx >= header_.e_shnum) {
        throw std::runtime_error("Section index out of bounds");
    }
    auto sectionHeader = sectionHeaders_[idx];
    auto it = sectionsStringTable_.upper_bound(sectionHeader.sh_name);
    it--;
    if (it->first + it->second.size() < sectionHeader.sh_name) {
        std::cerr << "INVALID OFFSET: " << sectionHeader.sh_name << std::endl;
        throw std::runtime_error("Invalid offset for section name");
    }
	if (it->first == sectionHeader.sh_name) {
		return it->second;
	}
	std::string_view str = it->second.data() + (sectionHeader.sh_name - it->first);
	return str;
}

}; // namespace binary
