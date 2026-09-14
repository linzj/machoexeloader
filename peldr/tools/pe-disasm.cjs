const fs = require("fs");
const { Capstone, loadCapstone } = require("../tmp/cap/node_modules/capstone-wasm/dist/index.cjs");
(async () => {
await loadCapstone();
const file = process.argv[2];
const rva = parseInt(process.argv[3], 16);
const len = parseInt(process.argv[4], 16);
const B = fs.readFileSync(file);
const e = B.readUInt32LE(0x3c);
const nsec = B.readUInt16LE(e + 6);
const optsz = B.readUInt16LE(e + 20);
const opt = e + 24;
const imageBase = Number(B.readBigUInt64LE(opt + 24));
const secs = [];
const so = opt + optsz;
for (let i = 0; i < nsec; i++) {
    const p = so + i * 40;
    secs.push({
        name: B.toString("latin1", p, p + 8).replace(/\0.*/, ""),
        vs: B.readUInt32LE(p + 8),
        va: B.readUInt32LE(p + 12),
        rs: B.readUInt32LE(p + 16),
        pr: B.readUInt32LE(p + 20),
    });
}
const r2o = (r) => {
    for (const s of secs) {
        if (r >= s.va && r < s.va + Math.max(s.vs, s.rs)) return s.pr + (r - s.va);
    }
    return -1;
};
const off = r2o(rva);
if (off < 0) {
    console.log("rva not mapped to file");
    process.exit(1);
}
const code = new Uint8Array(B.buffer, B.byteOffset + off, len);
const md = new Capstone(3, 8);
for (const ins of md.disasm(code, { address: imageBase + rva })) {
    console.log(
        ins.address.toString(16).padStart(12, "0") +
            ": " +
            (ins.mnemonic + " " + ins.opStr).padEnd(56)
    );
}
})();
