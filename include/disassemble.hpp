#ifndef _DISASSEMBLE_HPP_
#define _DISASSEMBLE_HPP_

#include <cstdint>
#include <span>
#include <string>

namespace disassemble {

enum class ReadingMode {
    LSB,
    MSB,
};

std::string disassembleX86_64(const std::span<const uint8_t> code, ReadingMode readingMode);

};

#endif
