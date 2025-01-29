#include <algorithm>
#include <cassert>
#include <disassemble.hpp>
#include <format>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace disassemble {

namespace X86_64 {

namespace old {

enum class Register {
    RAX = 0b000,
    RCX = 0b001,
    RDX = 0b010,
    RBX = 0b011,
    RSP = 0b100,
    RBP = 0b101,
    RSI = 0b110,
    RDI = 0b111,
};

[[nodiscard]] inline bool isNegative(uint64_t value, size_t size) noexcept {
    return (value >> (8 * size - 1)) != 0;
}

struct Constant {
    uint64_t value;
    size_t size;
};

[[nodiscard]] inline bool isNegative(Constant constant) noexcept {
    return isNegative(constant.value, constant.size);
}

void writeRegister(std::ostream &out, Register reg, size_t regSize,
                   bool extended = false) {
    if (extended) {
        out << 'r' << 8 + (int)reg;
        return;
    }
    if (regSize == 1) {
        // Special case
        switch (reg) {
        case Register::RAX:
            out << "al";
            break;
        case Register::RCX:
            out << "cl";
            break;
        case Register::RDX:
            out << "dl";
            break;
        case Register::RBX:
            out << "bl";
            break;
        case Register::RSP:
            out << "sp";
            break;
        case Register::RBP:
            out << "bp";
            break;
        case Register::RSI:
            out << "si";
            break;
        case Register::RDI:
            out << "di";
            break;
        }
        return;
    }
    if (regSize == 2) {
        // Do nothing
    } else if (regSize == 4) {
        out << 'e';
    } else if (regSize == 8) {
        out << 'r';
    } else {
        throw std::runtime_error("Invalid register size");
    }
    switch (reg) {
    case Register::RAX:
        out << "ax";
        break;
    case Register::RCX:
        out << "cx";
        break;
    case Register::RDX:
        out << "dx";
        break;
    case Register::RBX:
        out << "bx";
        break;
    case Register::RSP:
        out << "sp";
        break;
    case Register::RBP:
        out << "bp";
        break;
    case Register::RSI:
        out << "si";
        break;
    case Register::RDI:
        out << "di";
        break;
    }
}

struct Prefix {
    enum class SegmentOverride {
        CS,
        SS,
        DS,
        ES,
        FS,
        GS,
        None,
    };
    SegmentOverride segOverride;
    Prefix() { segOverride = SegmentOverride::None; }
    void setSegmentOverride(uint8_t value) {
        if (value == 0x2e) {
            segOverride = SegmentOverride::CS;
        } else if (value == 0x36) {
            segOverride = SegmentOverride::SS;
        } else if (value == 0x3e) {
            segOverride = SegmentOverride::DS;
        } else if (value == 0x26) {
            segOverride = SegmentOverride::ES;
        } else if (value == 0x64) {
            segOverride = SegmentOverride::FS;
        } else if (value == 0x65) {
            segOverride = SegmentOverride::GS;
        } else {
            segOverride = SegmentOverride::None;
        }
    }
};

struct RexPrefix {
    bool present;
    unsigned int w : 1;
    unsigned int r : 1;
    unsigned int x : 1;
    unsigned int b : 1;

    RexPrefix(uint8_t byte) {
        w = (byte >> 3) & 1;
        r = (byte >> 2) & 1;
        x = (byte >> 1) & 1;
        b = byte & 1;
        present = true;
    }

    RexPrefix() { present = false; }
};

struct ModRM {
    bool present;
    unsigned int mod : 2;
    unsigned int reg : 3;
    unsigned int rm : 3;

    ModRM() { present = false; }

    ModRM(uint8_t byte) {
        mod = byte >> 6;
        reg = (byte >> 3) & 0b111;
        rm = byte & 0b111;
        present = true;
    }
};

struct SIB {
    bool present;
    unsigned int scale : 2;
    unsigned int index : 3;
    unsigned int base : 3;
    SIB() { present = false; }
    SIB(uint8_t value) {
        scale = value >> 6;
        index = (value >> 3) & 0b111;
        base = value & 0b111;
        present = true;
    }
};

struct Instruction {
    Prefix prefix;
    RexPrefix rexPrefix;
    uint16_t opcode;
    ModRM modRM;
    SIB sib;
    Constant addressOffset;
    Constant immediate;
};

enum class OperandType {
    I,
    MI,
    RM,
    MR,
    O,
};

OperandType getOperandType(const Instruction &ins) {
    switch (ins.opcode) {
    case 0x31:
        return OperandType::MR;
    case 0x50:
    case 0x51:
    case 0x52:
    case 0x53:
    case 0x54:
    case 0x55:
    case 0x56:
    case 0x57:
    case 0x58:
    case 0x59:
    case 0x5a:
    case 0x5b:
    case 0x5c:
    case 0x5d:
    case 0x5e:
    case 0x5f:
        return OperandType::O;
    case 0x81:
        if (ins.modRM.reg == 5) {
            return OperandType::MI;
        } else if (ins.modRM.reg == 0) {
            return OperandType::MI;
        } else if (ins.modRM.reg == 7) {
            return OperandType::MI;
        }
        break;
    case 0x83:
        if (ins.modRM.reg == 7) {
            return OperandType::MI;
        }
        break;
    case 0x89:
        return OperandType::MR;
    case 0x8b:
        return OperandType::RM;
    }
    throw std::runtime_error("Unimplemented case");
}

Constant readConstant(const std::span<const uint8_t> code, size_t &offset,
                      ReadingMode mode, size_t size) {
    uint64_t value = 0;
    switch (mode) {
    case ReadingMode::LSB:
        for (size_t i = 0; i < size; i++) {
            value |= ((uint64_t)code[offset]) << (8 * i);
            offset++;
        }
        break;
    case ReadingMode::MSB:
        for (size_t i = 0; i < size; i++) {
            value <<= 8;
            value |= ((uint64_t)code[offset]);
            offset++;
        }
        break;
    }
    return Constant{.value = value, .size = size};
}

bool requiresOperandByte(uint8_t opcode) {
    static const std::set<uint8_t> list = {
        0x29, 0x31, 0x32, 0x33, 0x38, 0x81, 0x83, 0x89, 0x8b,
    };
    return list.count(opcode);
}

void writeConstantHex(std::ostream &out, Constant constant,
                      bool writeSign = true) {
    if (isNegative(constant)) {
        int64_t val = constant.value | ~((1ull << (8 * constant.size)) - 1);
        if (writeSign) {
            out << std::format("-0x{:x}", -val);
        } else {
            out << std::format("0x{:x}", -val);
        }
    } else {
        out << std::format("0x{:x}", constant.value);
    }
}

void writeOperandRM(std::ostream &out, const Instruction &ins,
                    size_t operandSize) {
    if (ins.prefix.segOverride != Prefix::SegmentOverride::None) {
        // Segment override present
        // TODO: Implement segment overrides
        out << "TODO(segment override)";
        return;
    }
    if (ins.modRM.mod == 0) {
        out << '[';
        if (ins.modRM.rm == 5) {
            out << "rip ";
            if (isNegative(ins.addressOffset)) {
                out << "- ";
            } else {
                out << "+ ";
            }
            writeConstantHex(out, ins.addressOffset, false);
        } else if (ins.modRM.rm == 4) {
            out << "sib";
        } else {
            writeRegister(out, (Register)ins.modRM.rm, operandSize,
                          ins.rexPrefix.present && ins.rexPrefix.b == 1);
        }
        out << ']';
        return;
    } else if (ins.modRM.mod == 1 || ins.modRM.mod == 2) {
        out << '[';
        if (ins.modRM.rm == 4) {
            out << "sib ";
        } else {
            writeRegister(out, (Register)ins.modRM.rm, operandSize,
                          ins.rexPrefix.present && ins.rexPrefix.b == 1);
            out << " ";
        }
        if (ins.modRM.mod == 1) {
            if (isNegative(ins.addressOffset)) {
                out << "- ";
            } else {
                out << "+ ";
            }
            writeConstantHex(out, ins.addressOffset, false);
        } else {
            if (isNegative(ins.addressOffset)) {
                out << "- ";
            } else {
                out << "+ ";
            }
            writeConstantHex(out, ins.addressOffset, false);
        }
        out << ']';
        return;
    } else if (ins.modRM.mod == 3) {
        writeRegister(out, (Register)ins.modRM.rm, operandSize,
                      ins.rexPrefix.present && ins.rexPrefix.b == 1);
        return;
    }
    const bool unreachable = false;
    assert(unreachable);
}

void readIns(std::ostream &out, const std::span<const uint8_t> code,
             size_t &offset, ReadingMode readingMode) {
    size_t sizeMode = 4;
    Instruction ins;
    uint8_t byte = code[offset];
    if (byte == 0x64 || byte == 0x65 || byte == 0x26 || byte == 0x3E ||
        byte == 0x36 || byte == 0x2E) {
        ins.prefix.setSegmentOverride(byte);
        offset++;
        byte = code[offset];
    }
    if (byte == 0x66) {
        sizeMode = 2;
        offset++;
        byte = code[offset];
    }
    if ((byte & 0xf0) == 0x40) {
        // REX prefix
        ins.rexPrefix = byte;
        if (ins.rexPrefix.w) {
            sizeMode = 8;
        }
        offset++;
        byte = code[offset];
    }
    // At this point, 'byte' should hold the opcode
    ins.opcode = byte;
    offset++;
    if (requiresOperandByte(ins.opcode)) {
        ins.modRM = code[offset];
        offset++;
    }
    OperandType opType;
    try {
        opType = getOperandType(ins);
    } catch (...) {
        out << "\tUnimplemented: " << std::format("{:02x}", ins.opcode)
            << std::endl;
        return;
    }
    switch (opType) {
    case OperandType::RM:
    case OperandType::MR:
    case OperandType::MI:
        if (!ins.modRM.present) {
            ins.modRM = code[offset];
            offset++;
        }
        if (ins.modRM.rm == 4 && ins.modRM.mod != 3) {
            ins.sib = code[offset];
            offset++;
            if (ins.sib.base == 5) {
                if (ins.modRM.mod == 1) {
                    ins.addressOffset =
                        readConstant(code, offset, readingMode, 1);
                } else {
                    ins.addressOffset =
                        readConstant(code, offset, readingMode, 4);
                }
                break;
            }
        }
        if (ins.modRM.mod == 0) {
            if (ins.modRM.rm == 5) {
                ins.addressOffset = readConstant(code, offset, readingMode, 4);
            }
        } else if (ins.modRM.mod == 1) {
            ins.addressOffset = readConstant(code, offset, readingMode, 1);
        } else if (ins.modRM.mod == 2) {
            ins.addressOffset = readConstant(code, offset, readingMode, 4);
        }
        break;
    case OperandType::I:
        break;
    case OperandType::O:
        break;
    }
    switch (ins.opcode) {
    case 0x31:
        out << "\txor ";
        writeOperandRM(out, ins, sizeMode);
        out << ", ";
        writeRegister(out, (Register)ins.modRM.reg, sizeMode,
                      ins.rexPrefix.present && ins.rexPrefix.b == 1);
        out << std::endl;
        return;
    case 0x50:
    case 0x51:
    case 0x52:
    case 0x53:
    case 0x54:
    case 0x55:
    case 0x56:
    case 0x57:
        // push
        sizeMode = 8;
        out << "\tpush ";
        writeRegister(out, (Register)(ins.opcode & 0xf), sizeMode,
                      ins.rexPrefix.present && ins.rexPrefix.b == 1);
        out << std::endl;
        return;
    case 0x81:
        if (!ins.rexPrefix.present || !ins.rexPrefix.w) {
            ins.immediate = readConstant(code, offset, readingMode, sizeMode);
            if (ins.modRM.reg == 0) {
                // Add
                out << "\tadd ";
                writeOperandRM(out, ins, sizeMode);
                out << ", ";
                writeConstantHex(out, ins.immediate);
                out << std::endl;
            } else if (ins.modRM.reg == 5) {
                out << "\tsub ";
                writeOperandRM(out, ins, sizeMode);
                out << ", ";
                writeConstantHex(out, ins.immediate);
                out << std::endl;
            }
            return;
        }
        if (ins.modRM.reg == 0) {
            // ADD
            ins.immediate = readConstant(code, offset, readingMode, 4);
            out << "\tadd ";
            writeOperandRM(out, ins, 8);
            out << ", ";
            writeConstantHex(out, ins.immediate);
            out << std::endl;
        } else if (ins.modRM.reg == 5) {
            // SUB
            ins.immediate = readConstant(code, offset, readingMode, 4);
            out << "\tsub ";
            writeOperandRM(out, ins, 8);
            out << ", ";
            writeConstantHex(out, ins.immediate);
            out << std::endl;
        }
        return;
    case 0x83:
        if (ins.modRM.reg == 7) {
            out << "\tcmp ";
            writeOperandRM(out, ins, sizeMode);
            out << ", ";
            writeConstantHex(out, ins.immediate);
            out << std::endl;
            return;
        }
        break;
    case 0x89:
        out << "\tmov ";
        writeOperandRM(out, ins, sizeMode);
        out << ", ";
        writeRegister(out, (Register)ins.modRM.reg, sizeMode);
        out << std::endl;
        return;
    case 0x8b:
        out << "\tmov ";
        writeRegister(out, (Register)ins.modRM.reg, sizeMode);
        out << ", ";
        writeOperandRM(out, ins, sizeMode);
        out << std::endl;
        return;
    }
    out << "\tUnimplemented: " << std::format("{:02x}", ins.opcode)
        << std::endl;
}

}; // namespace old

enum class Register {
    RAX = 0b000,
    RCX = 0b001,
    RDX = 0b010,
    RBX = 0b011,
    RSP = 0b100,
    RBP = 0b101,
    RSI = 0b110,
    RDI = 0b111,
};

enum class OperandModel {
    None,
    RegSize,
    Reg32,
    Reg64,
    RmSize,
    Rm32,
    Rm64,
    ImmSize,
    Imm8,
    Imm32,
};

enum class RegSpec {
    None,
    R,
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,
};

class InstructionModel {
  public:
    InstructionModel(std::initializer_list<uint8_t> opcode, RegSpec regSpec,
                     std::string_view mnemonic, OperandModel operand1,
                     OperandModel operand2) {
        opcode_ = opcode;
        mnemonic_ = mnemonic;
        if ((opcode_[0] & 0xf0) == 0x40) {
            if ((opcode_[0] & 0x8) != 0) {
                rexPrefixConfig_ = RexPrefixConfig::RexW;
            } else {
                rexPrefixConfig_ = RexPrefixConfig::Rex;
            }
        } else {
            rexPrefixConfig_ = RexPrefixConfig::None;
        }
        op1_ = operand1;
        op2_ = operand2;
        regSpec_ = regSpec;
    }

    [[nodiscard]] bool requiresModRMByte() const noexcept {
        return regSpec_ != RegSpec::None;
    }

  private:
    enum class RexPrefixConfig {
        None,
        Rex,
        RexW,
    };
    std::vector<uint8_t> opcode_;
    RexPrefixConfig rexPrefixConfig_;
    std::string_view mnemonic_;
    RegSpec regSpec_;
    OperandModel op1_;
    OperandModel op2_;
};

static const std::vector<InstructionModel> instructionSet = {
    InstructionModel({0x81}, RegSpec::R0, "add", OperandModel::RmSize,
                     OperandModel::ImmSize),
    InstructionModel({0x48, 0x81}, RegSpec::R0, "add", OperandModel::Rm64,
                     OperandModel::Imm32),
};

class Trie {
  public:
    Trie() { nodes_.emplace_back(); }

    void insert(std::vector<uint8_t> prefix, size_t instructionIdx) {
        size_t position = 0;
        for (uint8_t byte : prefix) {
            if (!nodes_[position].children.count(byte)) {
                nodes_[position].children.insert({byte, nodes_.size()});
				nodes_.emplace_back();
            }
			position = nodes_[position].children.at(byte);
        }
		nodes_[position].instructionId = instructionIdx;
    }

  private:
    struct Node {
        std::optional<size_t> instructionId;
        std::map<uint8_t, size_t> children;
    };
    std::vector<Node> nodes_;
};

std::vector<size_t>
getInstructionsThatMatchSpec(const std::vector<uint8_t> &spec) {
    if (spec.empty()) {
        return {};
    }
    // TODO: Implement this
    return {0};
}

struct Constant {
    uint64_t value;
    size_t size;
};

class InstructionDecoder {
  public:
    InstructionDecoder(const std::span<const uint8_t> data,
                       ReadingMode readingMode)
        : data_(data), readingMode_(readingMode), offset_(0) {}

    [[nodiscard]] bool done() const noexcept { return offset_ >= data_.size(); }

  private:
    std::vector<uint8_t> readNextInstructionBytes() {
        std::vector<uint8_t> ins;
        while (isPrefixByte(currentByte())) {
            ins.push_back(getByte());
        }
        if (isRexPrefixByte(currentByte())) {
            ins.push_back(getByte());
        }

        ins.push_back(getByte());

        std::vector<size_t> possibleInstructions =
            getInstructionsThatMatchSpec(ins);

        bool requiresModRM = std::any_of(
            possibleInstructions.begin(), possibleInstructions.end(),
            [](size_t id) { return instructionSet[id].requiresModRMByte(); });

        if (requiresModRM) {
            ins.push_back(getByte());
        }
        return ins;
    }

    [[nodiscard]] Constant readConstant(size_t size) noexcept {
        uint64_t value = 0;
        switch (readingMode_) {
        case ReadingMode::LSB:
            for (size_t i = 0; i < size; i++) {
                value |= ((uint64_t)getByte()) << (8 * i);
            }
            break;
        case ReadingMode::MSB:
            for (size_t i = 0; i < size; i++) {
                value <<= 8;
                value |= (uint64_t)getByte();
            }
            break;
        }
        return Constant{.value = value, .size = size};
    }

    [[nodiscard]] inline uint8_t getByte() noexcept {
        uint8_t byte = currentByte();
        advance();
        return byte;
    }

    [[nodiscard]] inline uint8_t currentByte() const noexcept {
        return data_[offset_];
    }

    inline void advance() noexcept { offset_++; }

    [[nodiscard]] bool isRexPrefixByte(uint8_t byte) const noexcept {
        return (byte & 0xf0) == 0x40;
    }

    [[nodiscard]] bool isPrefixByte(uint8_t byte) const noexcept {
        auto prefixBytes = {
            0x64,
            0x65,
        };
        for (uint8_t b : prefixBytes) {
            if (byte == b) {
                return true;
            }
        }
        return false;
    }

  private:
    const std::span<const uint8_t> data_;
    ReadingMode readingMode_;
    size_t offset_;
};

}; // namespace X86_64

std::string disassembleX86_64(const std::span<const uint8_t> code,
                              ReadingMode readingMode) {
    std::stringstream result;
    size_t offset = 0;
    while (offset < code.size()) {
        X86_64::old::readIns(result, code, offset, readingMode);
    }
    return result.str();
}

}; // namespace disassemble
