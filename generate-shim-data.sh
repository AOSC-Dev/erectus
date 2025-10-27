#!/bin/bash -ex

[[ -z "$LOONGARCH_CC" ]] && {
    echo "LOONGARCH_CC is not set. Please run CMake to configure the build first."
    exit 1
}
BINARY_DIR="${BINARY_DIR:-.}"

ASM_FILE="${BINARY_DIR}/shims.S"
# We purposefully do not accept CFLAGS and LDFLAGS here to ensure LTO and other stuff is not used.
${LOONGARCH_CC} shims.c -S -o "${ASM_FILE}" -I"${BINARY_DIR}" -Oz -ffunction-sections -fdata-sections

# remove dynamic relocation related code
sed -Ei 's|.*%[a-z0-9_]*\(__errno_location.errno_lut\)|// \0|g' "${ASM_FILE}"
REG="$(sed -En 's|.+addi.d\s+\$([a-z0-9]+).+__errno_location.errno_lut.+|\1|p' "${ASM_FILE}")"
[[ -z "$REG" ]] && {
    echo "Failed to find the register used for loading __errno_location.errno_lut"
    exit 1
}
sed -Ei 's|.*.rodata.__errno_location.errno_lut|// \0|g' "${ASM_FILE}"
sed -i '1h;1!H;$!d;x;s|.*(__errno_location.errno_lut)|&\n.set __errno_lut_distance, (__errno_location.errno_lut - .) >> 2\npcaddi  %SAVED_REG%, 0/*LD_OFFS*/|' "${ASM_FILE}"
sed -i "s|%SAVED_REG%|\$$REG|g" "${ASM_FILE}"
echo '.section .rodata.Ldist,"a",@progbits
.type Ldist,@object
Ldist:
.word __errno_lut_distance' >> "${ASM_FILE}"

${LOONGARCH_CC} "${ASM_FILE}" -c -o shims-new.o
OFFSET="$(objdump --section=.rodata.Ldist -s shims-new.o | sed -En 's|\s+0000 ([0-9a-f]+).+|\1|p')"
OFFSET_INT="0x${OFFSET:6:2}${OFFSET:4:2}${OFFSET:2:2}${OFFSET:0:2}"  # "byte-swap" from little-endian array to integer
echo "Calculated offset: $OFFSET_INT"
sed -i "s|0/\*LD_OFFS\*/|$OFFSET_INT|g" "${ASM_FILE}"

${LOONGARCH_CC} "${ASM_FILE}" -c -o shims-new.o
llvm-objcopy -O binary --only-section=.text.__errno_location shims-new.o - \
    | xxd -i -n errno_conversion \
    | sed 's|unsigned |static constexpr unsigned |g' > "$BINARY_DIR"/errno_conversion_code.hpp
