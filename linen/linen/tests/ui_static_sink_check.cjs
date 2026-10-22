'use strict';
/**
 * Static sink audit for the browser UI (CF-S1-G2).
 *
 * The report preview is inserted into the page as raw HTML
 * (`x-html="yamlPreviewHtml"`), so the whole safety argument rests on one
 * function chain.  This script checks that chain in two ways:
 *
 *   1. structurally, by reading the real source out of index.html - the
 *      innerHTML sink must be a <textarea> (whose content model is RCDATA,
 *      so nothing in it is ever parsed as markup) and the decoded value must
 *      be escaped before it is returned;
 *   2. behaviourally, by executing the real functions with hostile input and
 *      checking that the produced markup contains no live tags.
 *
 * The functions are extracted from index.html rather than copied, so the
 * check cannot drift away from the code it is supposed to audit.
 *
 * Exit code 0 means the chain is safe; 1 means the audit failed.
 */

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const INDEX_PATH = path.join(ROOT, 'linen', 'src', 'linen', 'server', 'static', 'index.html');

const failures = [];
const checks = [];

function check(name, condition, detail) {
  checks.push({ name, ok: Boolean(condition), detail: detail || '' });
  if (!condition) failures.push(`${name}${detail ? `: ${detail}` : ''}`);
}

function extractMethod(source, name) {
  const start = source.indexOf(`${name}(`);
  if (start < 0) throw new Error(`method ${name} not found in index.html`);
  const open = source.indexOf('{', start);
  let depth = 0;
  let end = -1;
  for (let i = open; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end < 0) throw new Error(`unbalanced braces while extracting ${name}`);
  return source.slice(start, end + 1);
}

// --- a textarea decodes character references and nothing else ---------------

const NAMED_REFERENCES = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: '\u00a0',
};

function decodeCharacterReferences(text) {
  return String(text).replace(
    /&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]*);/g,
    (match, body) => {
      if (body[0] === '#') {
        const code =
          body[1] === 'x' || body[1] === 'X'
            ? parseInt(body.slice(2), 16)
            : parseInt(body.slice(1), 10);
        return Number.isFinite(code) ? String.fromCodePoint(code) : match;
      }
      const key = body.toLowerCase();
      return Object.prototype.hasOwnProperty.call(NAMED_REFERENCES, key)
        ? NAMED_REFERENCES[key]
        : match;
    },
  );
}

const documentShim = {
  createElement(tag) {
    if (tag !== 'textarea') {
      throw new Error(`unexpected element created by the audited code: ${tag}`);
    }
    let raw = '';
    return {
      set innerHTML(value) {
        raw = String(value);
      },
      get innerHTML() {
        return raw;
      },
      get value() {
        return decodeCharacterReferences(raw);
      },
    };
  },
};

// --- the hostile inputs ----------------------------------------------------

const PAYLOADS = [
  {
    name: 'img-onerror',
    text: '<img src=x onerror=alert(1)>',
    expectText: '&lt;img',
  },
  {
    name: 'textarea-breakout',
    text: '</textarea><script>alert(1)</script>',
    expectText: '&lt;script&gt;',
  },
  {
    name: 'svg-onload',
    text: '<svg/onload=alert(1)>',
    expectText: '&lt;svg',
  },
  {
    name: 'entity-encoded-script',
    text: '&lt;script&gt;alert(1)&lt;/script&gt;',
    expectText: '&lt;script&gt;',
  },
  {
    name: 'bold-wrapped-payload',
    text: '**<img src=x onerror=alert(1)>**',
    expectText: '&lt;img',
  },
  {
    name: 'code-wrapped-payload',
    text: '`<img src=x onerror=alert(1)>`',
    expectText: '&lt;img',
  },
  {
    name: 'heading-line',
    text: '# <img src=x onerror=alert(1)>',
    expectText: '&lt;img',
  },
  {
    name: 'table-line',
    text: '| a | <img src=x onerror=alert(1)> |',
    expectText: '&lt;img',
  },
  {
    name: 'list-line',
    text: '- <img src=x onerror=alert(1)>',
    expectText: '&lt;img',
  },
  {
    name: 'code-block-line',
    text: '    <img src=x onerror=alert(1)>',
    expectText: '&lt;img',
  },
];

/**
 * Remove the tags the audited code is allowed to emit.  Whatever `<` or `>`
 * survives that removal would be a tag the code did not intend to write.
 */
function stripAllowedTags(html) {
  return String(html)
    .replace(/<\/?(?:div|strong|code)\b[^>]*>/gi, '')
    .replace(/<\/?(?:br|span)\b[^>]*>/gi, '');
}

function main() {
  const html = fs.readFileSync(INDEX_PATH, 'utf8');

  // --- structural checks ---------------------------------------------------
  check(
    'the raw HTML insertion point is the export preview',
    html.includes('x-html="yamlPreviewHtml"'),
    'index.html no longer binds yamlPreviewHtml as raw HTML',
  );

  let escapeHtml;
  let highlightReportInline;
  let highlightReport;
  try {
    escapeHtml = extractMethod(html, 'escapeHtml');
    highlightReportInline = extractMethod(html, 'highlightReportInline');
    highlightReport = extractMethod(html, 'highlightReport');
  } catch (error) {
    check('the audited methods can be extracted from index.html', false, String(error));
    return finish();
  }

  const ESCAPES = [
    { ch: '&', entity: '&amp;' },
    { ch: '<', entity: '&lt;' },
    { ch: '>', entity: '&gt;' },
    { ch: '"', entity: '&quot;' },
    { ch: "'", entity: '&#39;' },
  ];
  for (const item of ESCAPES) {
    const literal = item.ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const replaces = new RegExp(`\\.replace\\(\\s*/${literal}/g`);
    check(
      `escapeHtml escapes ${item.ch}`,
      replaces.test(escapeHtml) && escapeHtml.includes(`'${item.entity}'`),
      escapeHtml,
    );
  }
  check(
    'the innerHTML sink is a textarea, whose content model is RCDATA',
    highlightReportInline.includes("document.createElement('textarea')") &&
      /textarea\.innerHTML\s*=/.test(highlightReportInline),
    highlightReportInline,
  );
  check(
    'the decoded value is escaped before it is returned',
    highlightReportInline.includes('this.escapeHtml(textarea.value)'),
    highlightReportInline,
  );

  // --- behavioural checks --------------------------------------------------
  // The extracted sources are method shorthand, so they are evaluated in an
  // object literal: that keeps `this` bound to the object, exactly as it is
  // in the application, and lets the audited code reach the document shim.
  /* eslint-disable no-eval */
  const api = eval(`({ ${escapeHtml}, ${highlightReportInline}, ${highlightReport} })`);
  /* eslint-enable no-eval */
  const document = documentShim;
  const results = [];

  for (const payload of PAYLOADS) {
    const rendered = api.highlightReport(payload.text);
    const withoutAllowed = stripAllowedTags(rendered);
    const hasLiveMarkup = withoutAllowed.includes('<') || withoutAllowed.includes('>');
    check(
      `highlightReport emits no live markup for ${payload.name}`,
      !hasLiveMarkup,
      rendered,
    );
    check(
      `highlightReport propagates the input as escaped text for ${payload.name}`,
      rendered.includes(payload.expectText),
      rendered,
    );
    results.push({ name: payload.name, rendered });
  }

  // The inline variant is the one that owns the textarea sink, so it gets the
  // same treatment on its own.
  for (const payload of PAYLOADS) {
    const rendered = api.highlightReportInline(payload.text);
    const withoutAllowed = stripAllowedTags(rendered);
    check(
      `highlightReportInline emits no live markup for ${payload.name}`,
      !withoutAllowed.includes('<') && !withoutAllowed.includes('>'),
      rendered,
    );
  }

  return finish(results);
}

function finish(results) {
  const report = {
    ok: failures.length === 0,
    checks: checks.length,
    failures,
    results: results || [],
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (failures.length > 0) {
    process.stderr.write(`static sink audit failed:\n- ${failures.join('\n- ')}\n`);
    process.exit(1);
  }
  process.exit(0);
}

main();
