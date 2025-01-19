#include <elf.h>
#include <binary.hpp>
#include <iostream>

int main() {
	auto binary = Binary::fromFile("/bin/ls");
	if (binary.getClass() == Binary::ElfClass::Elf64) {
		std::cout << "Elf64" << std::endl;
		auto header = binary.getHeader64();
		if (header.e_machine == EM_X86_64) {
			std::cout << "X86_64" << std::endl;
		}
	} else if (binary.getClass() == Binary::ElfClass::Elf32) {
		std::cout << "Elf32" << std::endl;
		auto header = binary.getHeader64();
		if (header.e_machine == EM_X86_64) {
			std::cout << "X86_64" << std::endl;
		}
	}
    return 0;
}
