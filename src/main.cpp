#include <binary.hpp>
#include <elf.h>
#include <iostream>
#include <print>

int main() {
    auto bin = binary::fromFile("/bin/ls");
    if (auto elf32 = dynamic_cast<binary::Elf32 *>(bin.get())) {
        std::cerr << "Elf32" << std::endl;
        [[maybe_unused]] auto header = elf32->getHeader();
    } else if (auto elf64 = dynamic_cast<binary::Elf64 *>(bin.get())) {
        std::cerr << "Elf64" << std::endl;
        auto header = elf64->getHeader();
        std::cout << header.e_shnum << std::endl;
        for (int i = 0; i < header.e_shnum; i++) {
			std::println("section = {}, name = {}", i, elf64->getSectionName(i));
        }
    }
    return 0;
}
