// SPDX-FileCopyrightText: Copyright 2025 Anthon Open Source Community
// SPDX-License-Identifier: GPL-2.0-or-later

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

struct LoongPLTEntryData {
  int8_t saved_pc_reg;
  uint64_t saved_pc_value;
  uint64_t start_va;
  uint64_t target_va;
  int8_t jump_reg;
  uint64_t plt_start;
};

constexpr static uint32_t get_break_instruction(const uint16_t code) {
  return 0x2A0000 | (code & 0x7FFF);
}

template <uint8_t Shift, uint8_t NumArgs, uint8_t Padding,
          bool LastArgIsPointer>
constexpr std::array<uint32_t, NumArgs - Shift + Padding + 1>
build_stat_shifting_stubs() {
  static_assert(NumArgs >= Shift,
                "NumArgs must be greater than or equal to Shift");
  static_assert(NumArgs < 7,
                "NumArgs must be less than 7 to fit in available registers");
  std::array<uint32_t, NumArgs - Shift + Padding + 1> result = {0};
  constexpr const uint32_t a0_reg = 4;
  for (uint8_t i = 0; i < NumArgs - Shift; i++) {
    // move $aX, $aY (X = Y - 1)
    result[i] = 0x150000 | (a0_reg + i + 1) << 5 | (a0_reg + i);
  }
  if constexpr (LastArgIsPointer) {
    // ld.w $aX, 0($aY) (X = Y - 1)
    result[NumArgs - Shift] = 0x28800000 | (a0_reg + NumArgs - 1) << 5 |
                              (a0_reg + NumArgs - 1 - Shift);
  }

  return result;
}

constexpr static uint32_t encode_b26(const uint32_t from_addr,
                                     const uint32_t to_addr) {
  int64_t jump_dist =
      static_cast<int64_t>(to_addr) - static_cast<int64_t>(from_addr);
  uint32_t offset_26b = (static_cast<uint32_t>(jump_dist >> 2)) & 0x3FFFFFF;
  return (offset_26b >> 16) | ((offset_26b & 0xFFFF) << 10);
}

constexpr static std::pair<uint32_t, uint32_t>
encode_pcala_pair(const uint32_t from_addr, const uint32_t to_addr) {
  const int64_t hi20 = static_cast<int64_t>(to_addr + 0x800) -
                       (static_cast<int64_t>(from_addr) & (~0xFFFLL));
  const int64_t lo12 = static_cast<int64_t>(to_addr);
  return {(hi20 >> 12) & 0xFFFFF, lo12 & 0xFFF};
}

constexpr static std::array<uint32_t, 2>
encode_jump(const uint32_t from_addr, const uint32_t to_addr,
            const uint8_t tmp_reg = 20) {
  const int64_t offset =
      static_cast<int64_t>(to_addr) - static_cast<int64_t>(from_addr);
  if ((offset & 0x3) != 0) {
    // unaligned jump not supported
    return {0, 0};
  }
  const int64_t offset_insts = offset >> 2;
  // LoongArch B/BL instruction has a 26-bit signed immediate
  if (offset_insts >= -0x2000000 && offset_insts < 0x2000000) {
    const uint32_t encoded = encode_b26(from_addr, to_addr);
    return {0x50000000 | encoded, get_break_instruction(0)};
  } else {
    // out of range for B/BL, need to use jirl
    // strategy: use pcalau12i (set hi 20-bit) + jirl (set lo 12-bit)
    const auto [hi20, lo12] = encode_pcala_pair(from_addr, to_addr);
    // offset_lo = lo12 & ~0xFFF if lo12 & 0x800 else lo12 & 0xFFF
    const uint32_t offset_lo =
        (lo12 & 0x800) ? (lo12 & 0xFFFFF000) : (lo12 & 0xFFF);
    return {// pcalau12i <tmp_reg>, <hi20>
            0x1A000000 | ((hi20 & 0xFFFFF) << 5) | tmp_reg,
            // jirl zero, <tmp_reg>, <lo12>
            0x4C000000 | ((offset_lo & 0xFFFF) << 10) | (tmp_reg << 5) | 0};
  }
}

static constexpr auto stub_s1a3 = build_stat_shifting_stubs<1, 3, 0, false>();
static constexpr auto stub_s1a5 = build_stat_shifting_stubs<1, 5, 0, false>();
static constexpr auto stub_s1a4p = build_stat_shifting_stubs<1, 4, 0, true>();
static constexpr auto stub_s1a5p = build_stat_shifting_stubs<1, 5, 0, true>();

// generated code (see shims-new.S)
#include "errno_conversion_code.hpp"
// end of generated code
static_assert(sizeof(errno_conversion) == errno_conversion_len);

struct StubInfo {
  const uint32_t *code;
  size_t size;
  const bool allocated;
};

constexpr static const StubInfo
get_stat_stub(const std::string_view &func_name) {
  if (func_name == "__xstat64" || func_name == "__lxstat64" ||
      func_name == "__fxstat64" || func_name == "__xstat" ||
      func_name == "__lxstat" || func_name == "__fxstat") {
    return {stub_s1a3.data(), stub_s1a3.size()};
  } else if (func_name == "__fxstatat64") {
    return {stub_s1a5.data(), stub_s1a5.size()};
  } else if (func_name == "__xmknod") {
    return {stub_s1a4p.data(), stub_s1a4p.size()};
  } else if (func_name == "__xmknodat") {
    return {stub_s1a5p.data(), stub_s1a5p.size()};
  }
  return {nullptr, 0};
}

constexpr static const char *
get_new_symbol_name(const std::string_view &old_name) {
  if (old_name == "__errno_location") {
    return "__errno_location";
  } else if (old_name == "__xstat64" || old_name == "__xstat") {
    return "stat64";
  } else if (old_name == "__lxstat64" || old_name == "__lxstat") {
    return "lstat64";
  } else if (old_name == "__fxstat64" || old_name == "__fxstat") {
    return "fstat64";
  } else if (old_name == "__fxstatat64") {
    return "fstatat64";
  } else if (old_name == "__xmknod") {
    return "mknod";
  } else if (old_name == "__xmknodat") {
    return "mknodat";
  }
  return nullptr;
}

constexpr static std::array<uint32_t, 5>
build_jump_back_to_plt(const uint64_t jump_out_pc,
                       const LoongPLTEntryData &old_plt_data,
                       const bool is_jal = false) {
  const auto [hi20, lo12] =
      encode_pcala_pair(jump_out_pc, old_plt_data.saved_pc_value);
  const auto [hi20_2, lo12_2] =
      encode_pcala_pair(jump_out_pc + 8, old_plt_data.target_va);
  const uint8_t jirl_rd = is_jal ? 1 : 0;
  std::array<uint32_t, 5> result = {
      // pcalau12i <saved_pc_reg>, <hi20>
      0x1A000000 | hi20 << 5 | old_plt_data.saved_pc_reg,
      // addi.d <saved_pc_reg>, <saved_pc_reg>, <lo12>
      0x2C00000 | lo12 << 10 | old_plt_data.saved_pc_reg << 5 |
          old_plt_data.saved_pc_reg,
      // pcalau12i <jump_reg>, <hi20>
      0x1A000000 | hi20_2 << 5 | old_plt_data.jump_reg,
      // ld.d <jump_reg>, <lo12>, 0
      0x28C00000 | lo12_2 << 10 | old_plt_data.jump_reg << 5 |
          old_plt_data.jump_reg,
      // jirl $r0/$ra, <jump_reg>, 0
      static_cast<unsigned int>(0x4C000000 | old_plt_data.jump_reg << 5 |
                                jirl_rd)};
  return result;
}

constexpr static std::array<uint32_t, 7 + 5>
build_errno_conversion_call_prologue(const uint64_t prologue_start_pc,
                                     const LoongPLTEntryData &old_plt_data) {
  // prototype for our shim function: void __errno_location(int *in_errnop, int
  // *out_errnop)
  // generate:
  // addi.d $sp, $sp, -16
  // st.d   $ra, $sp, 8
  // st.d   $fp, $sp, 0
  // ... build_jump_back_to_plt(jump_out_pc, old_plt_data);
  // ld.d   $fp, $sp, 0
  // ld.d   $ra, $sp, 8
  // addi.d $sp, $sp, 16
  // addi.d $a1, $sp, -128 # this is where the hack happens: stack is
  // thread-safe, we can store errno conversion results here (on the edge of the
  // red-zone)
  const std::array<uint32_t, 5> jump_back_to_plt_result =
      build_jump_back_to_plt(prologue_start_pc + 8, old_plt_data, true);
  return {
      // addi.d $sp, $sp, -16
      0x02FFC063,
      // st.d   $ra, $sp, 8
      0x29C02061,
      // st.d   $fp, $sp, 0
      0x29C00076,
      jump_back_to_plt_result[0],
      jump_back_to_plt_result[1],
      jump_back_to_plt_result[2],
      jump_back_to_plt_result[3],
      jump_back_to_plt_result[4],
      // ld.d   $fp, $sp, 0
      0x28C00076,
      // ld.d   $ra, $sp, 8
      0x28C02061,
      // addi.d $sp, $sp, 16
      0x02C04063,
      // addi.d $a1, $sp, -128
      0x02FE0065,
  };
}

static const StubInfo
get_function_patch_stub(const std::string_view &func_name,
                        uint64_t &patch_start_pc,
                        const LoongPLTEntryData &old_plt_data) {
  patch_start_pc = (patch_start_pc + 4) & ~0x3ULL;
  if (func_name == "__errno_location") {
    const auto code_array =
        build_errno_conversion_call_prologue(patch_start_pc, old_plt_data);
    constexpr const size_t code_size =
        code_array.size() * sizeof(uint32_t) + sizeof(errno_conversion);
    uint8_t *result = new uint8_t[code_size];
    __builtin_memcpy(result, code_array.data(),
                     code_array.size() * sizeof(uint32_t));
    __builtin_memcpy(result + code_array.size() * sizeof(uint32_t),
                     errno_conversion, sizeof(errno_conversion));
    return {reinterpret_cast<const uint32_t *>(result), code_size, true};
  }
  const auto stub_info = get_stat_stub(func_name);
  if (stub_info.size > 0) {
    const auto jump_back_code = build_jump_back_to_plt(
        patch_start_pc + (stub_info.size - 1) * sizeof(uint32_t), old_plt_data);
    const size_t code_size = jump_back_code.size() * sizeof(uint32_t) +
                             (stub_info.size - 1) * sizeof(uint32_t);
    uint32_t *code_array = new uint32_t[code_size / sizeof(uint32_t)];
    __builtin_memcpy(code_array, stub_info.code,
                     stub_info.size * sizeof(uint32_t));
    __builtin_memcpy(code_array + stub_info.size - 1, jump_back_code.data(),
                     jump_back_code.size() * sizeof(uint32_t));
    return {code_array, code_size, true};
  }
  return {nullptr, 0, false};
}