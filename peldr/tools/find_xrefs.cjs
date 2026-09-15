// Find RIP-relative refs to given RVAs within an RVA window (chunked disasm).
const fs = require("fs");
const { Capstone, loadCapstone } = require("../tmp/cap/node_modules/capstone-wasm/dist/index.cjs");
(async () => {
await loadCapstone();
const file = process.argv[2];
const lo = parseInt(process.argv[3], 16), hi = parseInt(process.argv[4], 16);
const targets = new Set(process.argv.slice(5).map(s => parseInt(s, 16)));
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
  secs.push({ name: B.toString("latin1", p, p + 8).replace(/\0.*/, ""), vs: B.readUInt32LE(p + 8), va: B.readUInt32LE(p + 12), rs: B.readUInt32LE(p + 16), pr: B.readUInt32LE(p + 20) });
}
const r2o = (r) => { for (const s of secs) if (r >= s.va && r < s.va + Math.max(s.vs, s.rs)) return s.pr + (r - s.va); return -1; };
const off = r2o(lo);
const len = hi - lo;
const md = new Capstone(3, 8);
let total = 0;
let pos = 0;
while (pos < len) {
  const avail = B.length - (B.byteOffset + off + pos);
  if (avail <= 0) break;
  const end = Math.min(pos + 256, len, pos + avail);
  const chunk = new Uint8Array(B.buffer, B.byteOffset + off + pos, end - pos);
  let consumed = 0;
  try {
    for (const ins of md.disasm(chunk, { address: imageBase + lo + pos })) {
      consumed = (ins.address - (imageBase + lo + pos)) + ins.size;
      const m = /rip ([+-]) 0x([0-9a-f]+)/.exec(ins.opStr);
      if (m) {
        const disp = parseInt(m[2], 16) * (m[1] === "-" ? -1 : 1);
        const tgt = ins.address + ins.size + disp - imageBase;
        if (targets.has(tgt)) {
          console.log(`RVA ${(ins.address - imageBase).toString(16)}: ${ins.mnemonic} ${ins.opStr}  => RVA ${tgt.toString(16)}`);
          total++;
        }
      }
    }
  } catch (err) { /* skip chunk */ }
  pos += (consumed || 1);
}
console.log("total:", total);
})();
