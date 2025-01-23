#include <disassemble.hpp>
#include <format>

namespace disassemble {

namespace X86_64 {

std::string readIns(const std::span<const uint8_t> code, size_t &offset) {
	std::string result = std::format("{:02x}", code[offset]);
	offset++;
	return result;
}

}; // namespace X86_64

std::string disassembleX86_64(const std::span<const uint8_t> code) {
    std::string result;
	size_t offset = 0;
	while (offset < code.size()) {
		result += X86_64::readIns(code, offset);
	}
    return result;
}

}; // namespace disassemble

