#ifndef _BINARY_HPP_
#define _BINARY_HPP_

#include <cstdint>
#include <elf.h>
#include <functional>
#include <map>
#include <memory>
#include <string_view>
#include <vector>

namespace binary {

class Binary {
  public:
    enum class Type {
        Elf32,
        Elf64,
    };

    size_t readIntRef(int8_t &ref, size_t position) const noexcept;
    size_t readIntRef(int16_t &ref, size_t position) const noexcept;
    size_t readIntRef(int32_t &ref, size_t position) const noexcept;
    size_t readIntRef(int64_t &ref, size_t position) const noexcept;
    size_t readIntRef(uint8_t &ref, size_t position) const noexcept;
    size_t readIntRef(uint16_t &ref, size_t position) const noexcept;
    size_t readIntRef(uint32_t &ref, size_t position) const noexcept;
    size_t readIntRef(uint64_t &ref, size_t position) const noexcept;

    virtual ~Binary() = default;

  protected:
    using ReaderFn =
        std::function<uint64_t(size_t, size_t, const std::vector<uint8_t> &)>;

    [[nodiscard]] Binary(Type type, std::vector<uint8_t> &&data,
                         ReaderFn reader);

    std::vector<uint8_t> &getData() noexcept;

  private:
    Type type_;
    std::vector<uint8_t> data_;
    ReaderFn reader_;
};

class Elf32 : public Binary {
  public:
    explicit Elf32(std::vector<uint8_t> &&data);

    [[nodiscard]] Elf32_Ehdr getHeader() const noexcept;
    [[nodiscard]] Elf32_Shdr getSectionHeader(size_t idx) const noexcept;
	[[nodiscard]] const std::string_view getSectionName(size_t idx) const;

  private:
    Elf32_Ehdr header_;
    std::vector<Elf32_Shdr> sectionHeaders_;
    std::map<size_t, std::string> sectionsStringTable_;
};

class Elf64 : public Binary {
  public:
    explicit Elf64(std::vector<uint8_t> &&data);

    [[nodiscard]] Elf64_Ehdr getHeader() const noexcept;
    [[nodiscard]] Elf64_Shdr getSectionHeader(size_t idx) const noexcept;
	[[nodiscard]] const std::string_view getSectionName(size_t idx) const;

  private:
    Elf64_Ehdr header_;
    std::vector<Elf64_Shdr> sectionHeaders_;
    std::map<size_t, std::string> sectionsStringTable_;
};

[[nodiscard]] std::unique_ptr<Binary> fromFile(std::string_view filepath);

} // namespace binary

#endif
