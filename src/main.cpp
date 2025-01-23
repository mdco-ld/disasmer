#include <binary.hpp>
#include <elf.h>
#include <iostream>
#include <print>

bool isNameMangled(std::string_view name) { return name.starts_with("_____Z"); }

size_t readSize(std::string_view data, size_t &position) {
	size_t ret = 0;
	while ('0' <= data[position] && data[position] <= '9') {
		ret *= 10;
		ret += data[position] - '0';
		position++;
	}
	return ret;
}

std::string demangleCpp([[maybe_unused]] std::string_view name) {
	std::string result;
	size_t offset = 2;
	if (name[offset] == 'N') {
	}
    return result;
}

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
        auto functions = elf64->getFunctions();
        for (auto function : functions) {
            std::println("function: {}", isNameMangled(function.name)
                                             ? demangleCpp(function.name)
                                             : function.name);
        }
    } else {
        std::cerr << "Unsupported file type" << std::endl;
    }
    return 0;
}
