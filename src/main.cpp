#include <binary.hpp>
#include <elf.h>
#include <iostream>
#include <print>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::println("Usage: {} <filename>", argv[0]);
        return 0;
    }
    auto bin = binary::fromFile(argv[1]);
    if (auto elf32 = dynamic_cast<binary::Elf32 *>(bin.get())) {
        std::cerr << "Elf32" << std::endl;
        [[maybe_unused]] auto header = elf32->getHeader();
    } else if (auto elf64 = dynamic_cast<binary::Elf64 *>(bin.get())) {
        std::cerr << "Elf64" << std::endl;
        auto header = elf64->getHeader();
        std::println("num sections = {}", header.e_shnum);
        for (int i = 0; i < header.e_shnum; i++) {
            std::println("section = {}, name = {}", i,
                         elf64->getSectionName(i));
        }
    } else {
        std::cerr << "Unsupported file type" << std::endl;
    }
    return 0;
}
