#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <functional>
#include <gelf.h>
#include <libelf.h>
#include <string_view>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "patching.hpp"

static const char NEW_GLIBC_VERSION[] = "GLIBC_2.36";

struct LoongArchContext {
  uint64_t regs[32];
  uint64_t pc;
};

struct LoongArchConstPropResult {
  uint64_t next_pc;
  bool will_jump;
  bool error;
};

using LoongArchConstPropMemFunc =
    std::function<uint64_t(LoongArchContext, uint64_t,
                           bool)>; // uint64_t (*mem_func)(LoongArchContext ctx,
                                   // uint64_t load_addr, bool is_load);
using GElf_ShdrMap = std::unordered_map<std::string_view, GElf_Shdr>;

template <typename T, unsigned bits>
static constexpr inline T sign_extend(T value) {
  const T mask = static_cast<T>(1) << (bits - 1);
  return (value ^ mask) - mask;
}

struct ELFAddress {
  uint64_t offset;
  uint64_t virtual_addr;
  uint64_t file_size;
};

class LoongArchInstructionBase {
public:
  virtual ~LoongArchInstructionBase() = default;
  virtual LoongArchConstPropResult
  constprop(LoongArchContext &ctx, uint64_t addr,
            LoongArchConstPropMemFunc mem_func) const = 0;
};

class LoongArchInstructionSimple : public LoongArchInstructionBase {
public:
  LoongArchInstructionSimple(uint32_t raw_instr)
      : raw(raw_instr), opcode(0), bad(false) {
    memset(regs, -1, 4);
    memset(imms, 0, 8);
    decode_instruction();
  }

  uint8_t get_reg(int i) const { return regs[i]; }
  uint32_t get_imm(int i) const { return imms[i]; }

  LoongArchConstPropResult
  constprop(LoongArchContext &ctx, uint64_t addr,
            LoongArchConstPropMemFunc mem_func) const override {
    ctx.regs[0] = 0;
    ctx.pc = addr;
    bool error = bad;
    // const prop for a few instructions
    switch (opcode) {
    case 0x20:
    case 0x21:
      // add
      ctx.regs[regs[2]] = ctx.regs[regs[0]] + ctx.regs[regs[1]];
      break;
    case 0xA:
    case 0xB:
      // addi
      ctx.regs[regs[1]] = ctx.regs[regs[0]] + sign_extend<int32_t, 16>(imms[0]);
      break;
    case 0x22:
    case 0x23:
      // sub
      ctx.regs[regs[2]] = ctx.regs[regs[0]] - ctx.regs[regs[1]];
      break;
    case 0x29:
      // and
      ctx.regs[regs[2]] = ctx.regs[regs[0]] & ctx.regs[regs[1]];
      break;
    case 0x82:
    case 0x83:
    case 0x8A:
    case 0x8B:
      // srli.d
      ctx.regs[regs[1]] = ctx.regs[regs[0]] >> imms[0];
      break;
    case 0xE:
      // PCADDU12I
      ctx.regs[regs[0]] = ctx.pc + (sign_extend<int32_t, 20>(imms[0]) << 12);
      // printf("PCADDU12I: pc=0x%lx, imm=0x%x, result=0x%lx -> reg = %d\n",
      // ctx.pc,
      //        imms[0], ctx.regs[regs[0]], regs[0]);
      break;
    case 0x13: {
      // jirl
      ctx.regs[regs[1]] = ctx.pc + 4;
      const int32_t imm = sign_extend<int32_t, 16>(imms[0] << 2);
      ctx.pc = ctx.regs[regs[0]] + imm;
      ctx.regs[0] = 0;
      return {ctx.pc, true, error};
    }
    default: { // memory instructions
      if (opcode >= 0xA0 && opcode <= 0xAF) {
        if (mem_func) {
          uint64_t addr = 0;
          if (opcode == 0xA3) { // ld.d
            const int32_t simm =
                sign_extend<int32_t, 12>(imms[0]); // sign extend
            addr = ctx.regs[regs[0]] + simm;
            // printf("addr = %02lx + %d = %02lx\n", ctx.regs[regs[0]], simm,
            // addr);
          } else {
            error = true;
          }
          uint64_t result = mem_func(ctx, addr, true);
          ctx.regs[regs[1]] = result;
        }
      } else {
        error = true;
      }
    }
    }
    ctx.regs[0] = 0;
    return {addr + 4, false, error};
  }

private:
  void decode_instruction() {
    uint32_t tmp = raw >> 10;
    if (tmp >= 4 && tmp <= 0x1B) {
      opcode = tmp;
      const uint32_t regs_int = raw & 0x3FF;
      // [rj, rd]
      regs[0] = (regs_int >> 5) & 0x1F;
      regs[1] = regs_int & 0x1F;
      return;
    }
    tmp = raw >> 15;
    if (tmp >= 0x2 && tmp <= 0x4F) {
      opcode = tmp;
      const uint32_t regs_int = (raw >> 5) & 0x3FFFF;
      // [rk, rj, rd]
      regs[0] = (regs_int >> 10) & 0x1F;
      regs[1] = (regs_int >> 5) & 0x1F;
      regs[2] = regs_int & 0x1F;
      // handle immediate
      const uint32_t opcode_hi = opcode & 0x1C;
      // alsl.w[u], bytepick.w
      if (opcode_hi >= 2 && opcode_hi <= 4) {
        imms[0] = opcode & 0x3;
      }
      // bytepick.d
      else if (opcode_hi == 6 || opcode_hi == 7) {
        imms[0] = opcode & 0x7;
      }
      return;
    }
    switch (tmp) {
    case 0x54:
    case 0x55:
    case 0x56: {
      opcode = tmp;
      imms[0] = raw & 0x7FFF;
      return;
    }
    case 0x58: {
      opcode = tmp;
      const uint32_t regs_int = (raw >> 5) & 0x3FFFF;
      // [rk, rj, rd]
      regs[0] = (regs_int >> 10) & 0x1F;
      regs[1] = (regs_int >> 5) & 0x1F;
      regs[2] = regs_int & 0x1F;
      imms[0] = opcode & 0x3;
      return;
    }
    }
    if (tmp >= 0x81 && tmp <= 0x9B) {
      opcode = tmp;
      const uint32_t regs_int = raw & 0x3FF;
      // [rj, rd]
      regs[0] = (regs_int >> 5) & 0x1F;
      regs[1] = regs_int & 0x1F;
      if (opcode & 2) {
        imms[0] = (raw >> 10) & 0x3F;
      } else {
        imms[0] = (raw >> 10) & 0x1F;
      }
      return;
    }
    tmp = raw >> 22;
    if (tmp >= 0xA0 && tmp <= 0xAF) {
      opcode = tmp;
      const uint32_t regs_int = raw & 0x3FF;
      // [rj, rd]
      regs[0] = (regs_int >> 5) & 0x1F;
      regs[1] = regs_int & 0x1F;
      imms[0] = (raw >> 10) & 0xFFF;
      return;
    }
    if (tmp >= 0x8 && tmp <= 0xC) {
      opcode = tmp;
      uint32_t imm = (raw >> 10) & 0xFFF;
      if (imm & 0x800) {
        imm |= ~0xFFF; // sign extend
      }
      imms[0] = imm;
      // [rj, rd]
      regs[0] = (raw >> 5) & 0x1F;
      regs[1] = raw & 0x1F;
      return;
    }
    tmp = raw >> 25;
    if (tmp >= 0x8 && tmp <= 0xF) {
      opcode = tmp;
      if (opcode == 0x8 || opcode == 0x9) {
        imms[0] = (raw >> 10) & 0xFFFF;
        // [rj, rd]
        regs[0] = (raw >> 5) & 0x1F;
        regs[1] = raw & 0x1F;
        return;
      }
      imms[0] = (raw >> 5) & 0xFFFFF;
      // [rd]
      regs[0] = raw & 0x1F;
      return;
    }
    tmp = raw >> 26;
    switch (tmp) {
    case 0x10:
    case 0x11: {
      opcode = tmp;
      imms[0] = (raw >> 10) & 0xFFFF;
      imms[1] = raw & 0x1F;
      return;
    }
    case 0x14:
    case 0x15: {
      // b/bl
      opcode = tmp;
      imms[0] = (raw >> 10) & 0xFFFF;
      imms[1] = raw & 0x3FF;
      return;
    }
    default:
      break;
    }
    if (tmp == 0x13 || (tmp >= 0x16 && tmp <= 0x1B)) {
      opcode = tmp;
      imms[0] = (raw >> 10) & 0xFFFF;
      // [rj, rd]
      regs[0] = (raw >> 5) & 0x1F;
      regs[1] = raw & 0x1F;
      return;
    }
    // we only care about a subset of integer instructions for now
    bad = true;
  }

  uint32_t raw;
  uint32_t opcode;
  int8_t regs[4];
  uint32_t imms[2];
  bool bad;
};

static bool set_obj_v1_flag(Elf *elf) {
  GElf_Ehdr ehdr{};
  if (gelf_getehdr(elf, &ehdr) == nullptr) {
    return false;
  }
  ehdr.e_flags |= EF_LARCH_OBJABI_V1;
  gelf_update_ehdr(elf, &ehdr);
  return true;
}

template <typename T> struct ModificationRecord {
  T start;
  T end;
  T used_offset;
  Elf_Type type;
  size_t index;
};

static ModificationRecord<uint64_t> find_executable_page_gap(Elf *elf) {
  // find the gap between the loadable sections (to see if we can fit our code
  // there to avoid adding new segments)
  GElf_Ehdr ehdr{};
  if (gelf_getehdr(elf, &ehdr) == nullptr) {
    return {0, 0};
  }
  std::vector<GElf_Phdr> segments{};
  segments.reserve(ehdr.e_phnum);
  for (size_t i = 0; i < ehdr.e_phnum; i++) {
    GElf_Phdr *backing_data = segments.data();
    if (gelf_getphdr(elf, i, &backing_data[i]) == nullptr) {
      return {0, 0};
    }
    segments.push_back(backing_data[i]);
  }
  std::vector<GElf_Phdr> sorted_segments{segments.begin(), segments.end()};
  std::sort(sorted_segments.begin(), sorted_segments.end(),
            [](const GElf_Phdr &a, const GElf_Phdr &b) {
              if (a.p_offset == b.p_offset)
                return a.p_offset + a.p_filesz < b.p_offset + b.p_filesz;
              return a.p_offset < b.p_offset;
            });

  // remove smaller overlapping segments from consideration
  for (size_t cursor = 0; cursor < sorted_segments.size() - 1;) {
    if (sorted_segments[cursor].p_offset + sorted_segments[cursor].p_filesz >
        sorted_segments[cursor + 1].p_offset) {
      // overlapping
      if (sorted_segments[cursor].p_offset + sorted_segments[cursor].p_filesz >=
          sorted_segments[cursor + 1].p_offset +
              sorted_segments[cursor + 1].p_filesz) {
        // remove next
        sorted_segments.erase(sorted_segments.begin() + cursor + 1);
      } else {
        // remove current
        sorted_segments.erase(sorted_segments.begin() + cursor);
      }
    } else {
      cursor++;
    }
  }
  for (size_t i = 0; i < sorted_segments.size(); i++) {
    printf("Segment %lu: 0x%lx - 0x%lx\n", i, sorted_segments[i].p_offset,
           sorted_segments[i].p_offset + sorted_segments[i].p_filesz);
    if ((sorted_segments[i].p_flags & PF_X) == 0 ||
        (sorted_segments[i].p_type != PT_LOAD)) {
      continue;
    }
    if (i + 1 < sorted_segments.size() &&
        sorted_segments[i + 1].p_offset ==
            sorted_segments[i].p_offset + sorted_segments[i].p_filesz) {
      // skip contiguous segments (can not fit anything)
      continue;
    }
    if (i + 1 >= sorted_segments.size()) {
      // last loadable segment, we can either fit nearly infinite data or we can do
      // nothing (e.g. section header follows this segment) depending on the ELF layout
      return {sorted_segments[i].p_offset + sorted_segments[i].p_filesz,
              UINT64_MAX};
    }
    const GElf_Phdr &target_segment = sorted_segments[i];
    int index =
        std::find_if(segments.begin(), segments.end(),
                     [target_segment](const auto &segment) {
                       return segment.p_offset == target_segment.p_offset &&
                              segment.p_filesz == target_segment.p_filesz;
                     }) -
        segments.begin();
    ModificationRecord<uint64_t> gap = {
        sorted_segments[i].p_offset + sorted_segments[i].p_filesz,
        sorted_segments[i + 1].p_offset,
        0,
        ELF_T_PHDR,
        static_cast<size_t>(index),
    };
    printf("Found executable gap: 0x%lx - 0x%lx after segment %ld\n", gap.start,
           gap.end, gap.index);
    printf("Space budget: %ld bytes\n", gap.end - gap.start);
    return gap;
  }

  return {0, 0};
}

static int patch_glibc_symbol_version(Elf *elf,
                                      const GElf_ShdrMap &section_headers) {
  const auto dynstrtab_section_it = section_headers.find(".dynstr");
  if (dynstrtab_section_it == section_headers.end()) {
    return -1;
  }
  const auto verneed_section_it = section_headers.find(".gnu.version_r");
  if (verneed_section_it == section_headers.end()) {
    return -1;
  }
  const GElf_Shdr &dynstr_shdr = dynstrtab_section_it->second;
  const GElf_Shdr &verneed_shdr = verneed_section_it->second;
  Elf_Data *verneed_data = elf_getdata_rawchunk(
      elf, verneed_shdr.sh_offset, verneed_shdr.sh_size, ELF_T_VNEED);
  Elf_Data *dynstr_data = elf_getdata_rawchunk(elf, dynstr_shdr.sh_offset,
                                               dynstr_shdr.sh_size, ELF_T_BYTE);
  if (dynstr_data == nullptr) {
    return -1;
  }
  if (verneed_data == nullptr) {
    return -1;
  }
  std::unordered_map<size_t, std::string_view> glibc_version_strings{};
  size_t offset = 0;
  while (offset < dynstr_data->d_size) {
    char *str = static_cast<char *>(dynstr_data->d_buf) + offset;
    if (strstr(str, "GLIBC_") == str) {
      glibc_version_strings[offset] = str;
    }
    offset += std::strlen(str) + 1;
  }

  if (glibc_version_strings.empty()) {
    return 0;
  }
  const auto patch_candidate =
      std::find_if(glibc_version_strings.begin(), glibc_version_strings.end(),
                   [](const auto &pair) {
                     const std::string_view ver_str = pair.second;
                     return ver_str.size() >= (sizeof(NEW_GLIBC_VERSION) - 1);
                   });
  if (patch_candidate == glibc_version_strings.end()) {
    // very rare situation, just return an error for now
    return -2;
  }
  // printf("Patching %s\n", patch_candidate->second.data());
  std::strcpy(const_cast<char *>(patch_candidate->second.data()),
              NEW_GLIBC_VERSION);
  memset(const_cast<char *>(patch_candidate->second.data()) +
             patch_candidate->second.size() + 1,
         0, patch_candidate->second.size() + 1 - sizeof(NEW_GLIBC_VERSION));

  size_t vernauxnum = 0;
  GElf_Verneed verneed{};
  for (size_t offset = 0;; offset += verneed.vn_next) {
    gelf_getverneed(verneed_data, offset, &verneed);
    printf("verneed: %hu %d %u\n", verneed.vn_version, verneed.vn_next,
           verneed.vn_aux);
    size_t vernaux_offset = offset + verneed.vn_aux;
    for (size_t sub_count = 0; sub_count < verneed.vn_cnt; sub_count++) {
      GElf_Vernaux vernaux{};
      gelf_getvernaux(verneed_data, vernaux_offset, &vernaux);
      printf("  vernaux: %u %u %u %u\n", vernaux.vna_hash, vernaux.vna_flags,
             vernaux.vna_other, vernaux.vna_name);
      // patch the name if matches
      const auto name_it = glibc_version_strings.find(vernaux.vna_name);
      if (name_it != glibc_version_strings.end()) {
        vernaux.vna_name = patch_candidate->first;
        vernaux.vna_hash = elf_hash(NEW_GLIBC_VERSION); // re-calculate the hash
        gelf_update_vernaux(verneed_data, vernaux_offset, &vernaux);
      }
      vernaux_offset += vernaux.vna_next;
    }
    if (!verneed.vn_next) {
      break;
    }
    vernauxnum += verneed.vn_cnt;
  }

  elf_flagdata(verneed_data, ELF_C_SET, ELF_F_DIRTY);

  // handle symbol rename for ___brk_addr
  const char old_name[] = "___brk_addr";
  const char new_name[] = "__curbrk";
  // the search contains the trailing null byte to avoid false positives
  void *sym_name_start = memmem(dynstr_data->d_buf, dynstr_data->d_size,
                                "___brk_addr", sizeof("___brk_addr"));
  if (sym_name_start) {
    std::memcpy(sym_name_start, new_name, sizeof(new_name));
    memset(reinterpret_cast<char *>(sym_name_start) + sizeof(new_name) + 1, 0,
           sizeof(old_name) - sizeof(new_name));
  }

  elf_flagdata(dynstr_data, ELF_C_SET, ELF_F_DIRTY);

  return 0;
}

static ELFAddress get_plt_address(Elf *elf,
                                  const GElf_ShdrMap &section_headers) {
  const auto &it = section_headers.find(".plt");
  if (it != section_headers.end()) {
    const GElf_Shdr &shdr = it->second;
    return {shdr.sh_offset, shdr.sh_addr, shdr.sh_size};
  }
  return {0, 0, 0};
}

static GElf_ShdrMap get_section_headers(Elf *elf) {
  GElf_ShdrMap section_headers{};
  Elf_Scn *scn = nullptr;
  size_t shstrndx = 0;
  if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
    return section_headers;
  }
  while ((scn = elf_nextscn(elf, scn))) {
    GElf_Shdr shdr{};
    if (!gelf_getshdr(scn, &shdr)) {
      continue;
    }
    const char *name = elf_strptr(elf, shstrndx, shdr.sh_name);
    if (name) {
      section_headers[name] = std::move(shdr);
    }
  }
  return section_headers;
}

static int patch_interpreter(Elf *elf, const GElf_ShdrMap &section_headers,
                             ModificationRecord<uint64_t> &gap) {
  const char new_interp[] = "/lib/ld-loongarch64-lp64d.so.1";
  if (gap.end - gap.start < sizeof(new_interp)) {
    return -1;
  }
  Elf_Data *data =
      elf_getdata_rawchunk(elf, gap.start, sizeof(new_interp), ELF_T_BYTE);
  __builtin_memcpy(reinterpret_cast<void *>(data->d_buf), new_interp,
                   sizeof(new_interp));
  elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
  GElf_Ehdr ehdr{};
  if (gelf_getehdr(elf, &ehdr) == nullptr) {
    return -1;
  }
  // change phdr
  GElf_Phdr phdr{};
  for (size_t i = 0; i < ehdr.e_phnum; ++i) {
    if (gelf_getphdr(elf, i, &phdr) == nullptr) {
      return -1;
    }
    if (phdr.p_type == PT_INTERP) {
      phdr.p_offset = gap.start;
      phdr.p_vaddr = gap.start; // TODO: proper virtual address
      phdr.p_paddr = gap.start;
      phdr.p_filesz = sizeof(new_interp);
      phdr.p_memsz = sizeof(new_interp);
      if (gelf_update_phdr(elf, i, &phdr) == 0) {
        return -1;
      }
      break;
    }
  }
  if (gelf_getphdr(elf, gap.index, &phdr) == nullptr) {
    return -1;
  }
  phdr.p_filesz += sizeof(new_interp);
  phdr.p_memsz += sizeof(new_interp);
  if (gelf_update_phdr(elf, gap.index, &phdr) == 0) {
    return -1;
  }
  // change shdr
  Elf_Scn *scn = nullptr;
  size_t shstrndx = 0;
  if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
    return -1;
  }
  while ((scn = elf_nextscn(elf, scn))) {
    GElf_Shdr shdr_mem{};
    GElf_Shdr *shdr = NULL;
    if (!(shdr = gelf_getshdr(scn, &shdr_mem))) {
      continue;
    }
    const char *name = elf_strptr(elf, shstrndx, shdr->sh_name);
    if (strcmp(name, ".interp") == 0) {
      Elf_Data *sh_data = NULL;
      if (!(sh_data = elf_getdata(scn, sh_data))) {
        return -1;
      }
      shdr->sh_offset = gap.start;
      shdr->sh_addr = gap.start; // TODO: proper virtual address
      shdr->sh_size = sizeof(new_interp);
      // this gymnastic is needed to avoid libelf from crashing on update_shdr
      sh_data->d_buf = data->d_buf;
      sh_data->d_size = data->d_size;
      sh_data->d_off = gap.start;
      if (gelf_update_shdr(scn, shdr) == 0) {
        return -1;
      }
      elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
      break;
    }
  }
  gap.used_offset += sizeof(new_interp);
  return 0;
}

static std::vector<LoongPLTEntryData>
parse_plt_entries(Elf *elf, const GElf_ShdrMap &section_headers) {
  const ELFAddress plt_address = get_plt_address(elf, section_headers);
  LoongArchContext ctx{};
  std::vector<LoongPLTEntryData> entries{};
  if (plt_address.virtual_addr == 0) {
    return {};
  }
  Elf_Data *elf_data_header = elf_getdata_rawchunk(
      elf, plt_address.offset, plt_address.file_size, ELF_T_BYTE);
  if (elf_data_header == nullptr) {
    return {};
  }
  unsigned char *elf_data =
      static_cast<unsigned char *>(elf_data_header->d_buf);
  // const uint64_t plt_end = plt_address.virtual_addr + plt_address.file_size;
  uint64_t start_va = plt_address.virtual_addr;
  for (uint64_t addr_offset = 0; addr_offset < plt_address.file_size;
       addr_offset += 4) {
    const uint64_t entry_va = plt_address.virtual_addr + addr_offset;
    uint32_t *inst_bin = reinterpret_cast<uint32_t *>(elf_data + addr_offset);
    LoongArchInstructionSimple instr(*inst_bin);
    LoongArchConstPropResult result = instr.constprop(
        ctx, entry_va,
        [](LoongArchContext, uint64_t addr, bool) { return addr; });
    if (result.error) {
      // TODO: Handle error
      fprintf(stderr, "Error constpropagating instruction at 0x%lx\n",
              entry_va);
      continue;
    }
    if (result.will_jump) {
      uint32_t saved_pc_value = 0;
      int8_t saved_pc_reg = -1;
      for (int i = 0; i < 32; i++) {
        const uint64_t reg_val = ctx.regs[i];
        // printf("Reg %d: 0x%lx\n", i, reg_val);
        if (reg_val != 0 && reg_val >= start_va && reg_val < entry_va) {
          saved_pc_reg = static_cast<int8_t>(i);
          saved_pc_value = reg_val;
          break;
        }
      }
      memset(&ctx, 0, sizeof(ctx));
      entries.push_back(
          LoongPLTEntryData{.saved_pc_reg = saved_pc_reg,
                            .saved_pc_value = saved_pc_value,
                            .start_va = start_va,
                            .target_va = result.next_pc,
                            .jump_reg = static_cast<int8_t>(instr.get_reg(0)),
                            .plt_start = plt_address.virtual_addr});
      start_va = entry_va + 4;
    }
  }

  return entries;
}

static Elf *elf_open(const char *file_name, bool read_only = true) {
  int fd = open(file_name, read_only ? O_RDONLY : O_RDWR);
  if (fd == -1) {
    return nullptr;
  }
  if (!elf_version(EV_CURRENT))
    return nullptr;
  Elf *elf =
      elf_begin(fd, read_only ? ELF_C_READ_MMAP : ELF_C_RDWR_MMAP, nullptr);
  if (elf == nullptr) {
    close(fd);
  }

  return elf;
}

static Elf *elf_copy_open(const char *src_name, const char *dst_name) {
  std::filesystem::copy_file(src_name, dst_name,
                             std::filesystem::copy_options::overwrite_existing);
  return elf_open(dst_name, false);
}

static int
patch_known_symbols(Elf *elf, const GElf_ShdrMap &section_headers,
                    const std::vector<LoongPLTEntryData> &plt_entries,
                    ModificationRecord<uint64_t> &gap) {
  Elf_Scn *scn = nullptr;
  const auto dynsym_it = section_headers.find(".dynsym");
  if (dynsym_it == section_headers.end()) {
    return -1;
  }
  const GElf_Shdr &dynsym_shdr = dynsym_it->second;
  Elf_Data *dynsym_data = elf_getdata_rawchunk(elf, dynsym_shdr.sh_offset,
                                               dynsym_shdr.sh_size, ELF_T_SYM);
  if (dynsym_data == nullptr) {
    return -1;
  }
  Elf_Data *dynstr_data =
      elf_getdata_rawchunk(elf, section_headers.at(".dynstr").sh_offset,
                           section_headers.at(".dynstr").sh_size, ELF_T_BYTE);
  if (dynstr_data == nullptr) {
    return -1;
  }
  while ((scn = elf_nextscn(elf, scn))) {
    GElf_Shdr shdr{};
    if (!gelf_getshdr(scn, &shdr)) {
      continue;
    }
    if (shdr.sh_type == SHT_RELA) {
      // process relocations
      Elf_Data *rela_data = elf_getdata(scn, nullptr);
      if (rela_data == nullptr) {
        continue;
      }
      for (size_t i = 0; i < rela_data->d_size / sizeof(Elf64_Rela); ++i) {
        GElf_Rela rela{};
        GElf_Sym sym{};
        gelf_getrela(rela_data, i, &rela);
        size_t sym_idx = GELF_R_SYM(rela.r_info);
        gelf_getsym(dynsym_data, sym_idx, &sym);
        const char *sym_name =
            elf_strptr(elf, dynsym_shdr.sh_link, sym.st_name);
        if (sym_name == nullptr || sym_name[0] == '\0') {
          continue;
        }
        printf("Relocation for symbol: %s (jump to) VA:0x%02lx\n", sym_name,
               rela.r_offset);
        const std::string_view sym_name_view(sym_name);
        const auto plt_entry_it =
            std::find_if(plt_entries.begin(), plt_entries.end(),
                         [rela](const LoongPLTEntryData &entry) {
                           return entry.target_va == rela.r_offset;
                         });
        if (plt_entry_it == plt_entries.end()) {
          continue;
        }
        const uint64_t unaligned_gap_start = gap.start + gap.used_offset;
        uint64_t gap_start = unaligned_gap_start;
        const StubInfo stub =
            get_function_patch_stub(sym_name_view, gap_start, *plt_entry_it);
        if (stub.size == 0) {
          continue;
        }
        if (gap.used_offset + stub.size > (gap.end - gap.start)) {
          fprintf(stderr, "Not enough space in the gap to insert stub for %s\n",
                  sym_name);
          return -1;
        }
        Elf_Data *stub_data =
            elf_getdata_rawchunk(elf, gap_start, stub.size, ELF_T_BYTE);
        if (stub_data == nullptr) {
          fprintf(stderr, "Error getting ELF code space for %s\n", sym_name);
          continue;
        }
        printf("Inserting stub for %s at VA:0x%02lx (size = %ld)\n", sym_name,
               gap_start, stub.size);
        memcpy(stub_data->d_buf, stub.code, stub.size);
        elf_flagdata(stub_data, ELF_C_SET, ELF_F_DIRTY);
        gap.used_offset += stub.size + (gap_start - unaligned_gap_start);
        if (stub.allocated) {
          delete[] stub.code;
        }
        printf("Patching PLT entry at VA:0x%02lx to jump to stub\n",
               plt_entry_it->start_va);
        // patch the PLT entry to jump to our stub
        Elf_Data *plt_data =
            elf_getdata_rawchunk(elf, plt_entry_it->start_va, 8, ELF_T_BYTE);
        if (plt_data == nullptr) {
          fprintf(stderr, "Error getting ELF PLT entry for %s\n", sym_name);
          continue;
        }
        memcpy(plt_data->d_buf,
               encode_jump(plt_entry_it->start_va, gap_start,
                           plt_entry_it->jump_reg)
                   .data(),
               8);
        elf_flagdata(plt_data, ELF_C_SET, ELF_F_DIRTY);
        const char *new_name = get_new_symbol_name(sym_name_view);
        const size_t new_name_len = strlen(new_name);
        const size_t old_name_len = strlen(sym_name);
        memcpy(reinterpret_cast<char *>(dynstr_data->d_buf) + sym.st_name,
               new_name, new_name_len + 1);
        memset(reinterpret_cast<char *>(dynstr_data->d_buf) + sym.st_name +
                   new_name_len + 1,
               0, old_name_len - new_name_len);
      }
    }
  }
  elf_flagdata(dynstr_data, ELF_C_SET, ELF_F_DIRTY);

  // patch phdr to extend the program's memory image
  GElf_Phdr phdr{};
  if (!gelf_getphdr(elf, gap.index, &phdr))
    return -1;
  phdr.p_filesz = phdr.p_filesz + gap.used_offset;
  phdr.p_memsz = phdr.p_memsz + gap.used_offset;
  gelf_update_phdr(elf, gap.index, &phdr);
  return 0;
}

static inline void elf_cleanup(Elf **elf) { elf_end(*elf); }

int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <input-elf> <output-elf>\n", argv[0]);
    return 2;
  }
  const char *input_elf_name = argv[1];
  const char *output_elf_name = argv[2];
  __attribute__((cleanup(elf_cleanup))) Elf *elf = elf_open(input_elf_name);
  __attribute__((cleanup(elf_cleanup))) Elf *out_elf = elf_copy_open(input_elf_name, output_elf_name);
  if (elf == nullptr) {
    if (errno != 0)
      perror("Error opening input ELF");
    else
      fprintf(stderr, "Error opening input ELF: %s\n", elf_errmsg(-1));
    return 1;
  }
  const GElf_ShdrMap section_headers = get_section_headers(elf);
  const std::vector<LoongPLTEntryData> plt_entries =
      parse_plt_entries(elf, section_headers);
  for (const auto &entry : plt_entries) {
    printf("PLT Entry: start_va=0x%lx, target_va=0x%lx, saved_pc_reg=%d, "
           "saved_pc_value=0x%lx, jump_reg=%d\n",
           entry.start_va, entry.target_va, entry.saved_pc_reg,
           entry.saved_pc_value, entry.jump_reg);
  }
  if (patch_glibc_symbol_version(out_elf, section_headers) != 0) {
    fprintf(stderr, "Error patching glibc symbol versions\n");
    return 1;
  }
  if (set_obj_v1_flag(out_elf) != true) {
    fprintf(stderr, "Error setting OBJABI v1 flag\n");
    return 1;
  }
  ModificationRecord<uint64_t> gap = find_executable_page_gap(elf);
  if (patch_interpreter(out_elf, section_headers, gap) != 0) {
    fprintf(stderr, "Error patching interpreter\n");
    return 1;
  }
  // set the new gap start after the interpreter and PLT
  gap.start += gap.used_offset;
  gap.used_offset = 0;
  if (patch_known_symbols(out_elf, section_headers, plt_entries, gap) != 0) {
    fprintf(stderr, "Error patching known symbols\n");
    return 1;
  }
  // tell libelf to re-write the ELF layout
  elf_flagelf(out_elf, ELF_C_SET, ELF_F_LAYOUT);
  elf_update(out_elf, ELF_C_WRITE);
  return 0;
}