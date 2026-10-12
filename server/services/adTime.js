// AD FILETIME (100-ns intervals since 1601) → Date; 0 and "never" (max int64) → null
const FILETIME_UNIX_EPOCH = 116444736000000000n;
const FILETIME_NEVER = 9223372036854775807n;

function fileTimeToDate(value) {
    if (!/^\d+$/.test(String(value ?? ''))) return null;
    const ticks = BigInt(value);
    if (ticks === 0n || ticks >= FILETIME_NEVER) return null;
    return new Date(Number((ticks - FILETIME_UNIX_EPOCH) / 10000n));
}

module.exports = { fileTimeToDate };
