#!/usr/bin/env node

// Windows-compatible runner for the vendored Cloudflare security-audit-skill
// validators.
//
// Why this file exists
// ---------------------
// `validate-coverage-ledger.cjs` and `validate-findings.cjs` open their input
// with `O_NOFOLLOW | O_NONBLOCK`. Node on win32 does not expose those
// constants (`fs.constants.O_NOFOLLOW` and `fs.constants.O_NONBLOCK` are
// `undefined`), so their file reader throws
// "OS no-follow and nonblocking input protection is unavailable" and the CLI
// exits 1 for *every* input — including a perfectly valid document.
//
// This runner restores the two sentinels with synthetic values and strips them
// again right before the real open, so the symlink/FIFO protection that cannot
// exist on Windows is the only behaviour lost. Every other upstream semantic
// check is preserved unchanged: regular-file check, byte limit, strict UTF-8
// decoding, JSON structure preflight and the full document validation.
//
// This file is authored by linen; it is NOT part of the upstream snapshot and
// is therefore not listed in SHA256SUMS. See PROVENANCE.md.
//
// Usage:
//   node run-validator.windows.cjs <validator.cjs> <input.json>
//
// Exit codes: 0 = valid, 1 = invalid or unreadable. Same contract as the
// upstream CLI.

const fs = require("node:fs");
const path = require("node:path");

const NOFOLLOW = 0x1000000;
const NONBLOCK = 0x2000000;

if (fs.constants.O_NOFOLLOW === undefined) {
  Object.defineProperty(fs.constants, "O_NOFOLLOW", { value: NOFOLLOW });
}
if (fs.constants.O_NONBLOCK === undefined) {
  Object.defineProperty(fs.constants, "O_NONBLOCK", { value: NONBLOCK });
}

const realOpenSync = fs.openSync;
fs.openSync = function patchedOpenSync(file, flags, mode) {
  if (typeof flags === "number") flags = flags & ~(NOFOLLOW | NONBLOCK);
  return realOpenSync.call(fs, file, flags, mode);
};

const validatorArg = process.argv[2];
const inputArg = process.argv[3];
if (!validatorArg || !inputArg) {
  console.error("Usage: node run-validator.windows.cjs <validator.cjs> <input.json>");
  process.exit(1);
}

const validatorPath = path.resolve(validatorArg);
const validator = require(validatorPath);

let errors = [];
let count = 0;
try {
  let contents;
  if (typeof validator.readFileWithinLimit === "function") {
    contents = validator.readFileWithinLimit(inputArg);
  } else {
    contents = fs.readFileSync(inputArg, "utf8");
  }
  if (typeof validator.preflightJsonText === "function") {
    validator.preflightJsonText(contents);
  }
  const document = JSON.parse(contents);
  count = Array.isArray(document) ? document.length : 0;
  const schemaPath = path.join(path.dirname(validatorPath), "report-schema.json");
  const schema = fs.existsSync(schemaPath)
    ? JSON.parse(fs.readFileSync(schemaPath, "utf8"))
    : undefined;
  errors = validator.validateDocument(document, schema);
} catch (error) {
  const reason = error && error.message ? error.message : String(error);
  console.error(`Failed to validate: ${reason}`);
  process.exit(1);
}

for (const message of errors) console.error("ERROR:", message);
if (errors.length > 0) {
  console.error(`FAIL: ${errors.length} validation error(s)`);
  process.exit(1);
}
console.log(`PASS: ${count} records valid`);
