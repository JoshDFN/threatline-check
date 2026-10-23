#!/usr/bin/env node
// Threatline check: find malicious, known exploited and critical dependencies in a repository.
//
// Reads lockfiles, SBOMs, Dockerfiles and compose files, downloads only the Threatline package indexes it
// needs, and matches versions on the runner. The list of dependencies is never sent anywhere.
// Runs as a GitHub Action (inputs from INPUT_* variables) or from a shell:
//   node index.mjs [path] [--fail-on exploited] [--api https://threatline.ai] [--ignore CVE-1,GHSA-2] [--json] [--sarif out.sarif]
import fs from 'node:fs/promises';
import path from 'node:path';
import './stackcore.js';

const T = globalThis.ThreatlineStack;
const env = process.env;
const VERSION = '1.0.0';
const DEFAULT_API = 'https://threatline.ai';
// The canister's own address, used when the default domain cannot be reached.
const FALLBACK_API = 'https://7zcj6-hqaaa-aaaao-bbqzq-cai.icp0.io';

// ---------------------------------------------------------------- options
const argv = process.argv.slice(2), flags = {};
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a.startsWith('--')) { const [k, v] = a.slice(2).split('='); flags[k] = v ?? (argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true'); } else flags.path ??= a;
}
const input = (name, def = '') => { const v = flags[name] ?? env[`INPUT_${name.toUpperCase()}`] ?? env[`INPUT_${name.toUpperCase().replace(/-/g, '_')}`]; return v === undefined || String(v).trim() === '' ? def : String(v).trim(); };
const bool = v => /^(1|true|yes|on)$/i.test(String(v));
const LEVELS = { malicious: 5, exploited: 4, critical: 3, high: 2, any: 1, none: 99 };
const opts = {
  root: path.resolve(input('path', '.')),
  failOn: input('fail-on', 'exploited').toLowerCase(),
  failWithoutFix: bool(input('fail-without-fix', 'false')),
  api: input('api', DEFAULT_API).replace(/\/+$/, ''),
  ignore: input('ignore', ''),
  ignoreFile: input('ignore-file', '.threatline-ignore'),
  token: input('github-token', ''),
  comment: bool(input('comment', 'true')),
  sarif: input('sarif-file', ''),
  report: input('report-file', ''),
  onApiError: input('on-api-error', 'warn').toLowerCase(),
  json: bool(input('json', 'false')),
};
if (!(opts.failOn in LEVELS)) die(`fail-on must be one of ${Object.keys(LEVELS).join(', ')}, not "${opts.failOn}"`);
const inActions = env.GITHUB_ACTIONS === 'true';
const esc = s => String(s ?? '').replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escProp = s => esc(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
function log(msg) { if (!opts.json) console.log(msg); }
function die(msg) { console.error(inActions ? `::error title=Threatline check::${esc(msg)}` : `threatline-check: ${msg}`); process.exit(2); }

// ---------------------------------------------------------------- data from the Threatline API
async function get(rel, { optional = false } = {}) {
  const url = `${opts.api}/${rel}`;
  for (let attempt = 1; ; attempt++) {
    try {
      const res = await fetch(url, { headers: { 'User-Agent': `threatline-check/${VERSION}`, Accept: 'application/json' } });
      if (res.status === 404 && optional) return null;
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      return await res.json();
    } catch (err) {
      if (attempt >= 3) { if (optional) return null; throw new Error(`${url}: ${err.message}`); }
      await new Promise(r => setTimeout(r, 800 * attempt));
    }
  }
}
async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } }));
  return out;
}

// ---------------------------------------------------------------- files in the repository
const SKIP = new Set(['node_modules', '.git', 'vendor', 'dist', 'build', '.venv', 'venv', 'env', 'target', '__pycache__', '.tox', '.next', '.nuxt', 'coverage', 'bower_components', '.terraform', '.gradle']);
async function discover(dir, depth = 0, found = []) {
  let entries = [];
  try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return found; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP.has(e.name) && depth < 8) await discover(full, depth + 1, found); continue; }
    if (!e.isFile()) continue;
    const rel = path.relative(opts.root, full).split(path.sep).join('/');
    if (T.LOCKFILE_RE.test(rel)) found.push({ rel, full, kind: 'lock' });
    else if (T.IMAGE_RE.test(rel)) found.push({ rel, full, kind: 'image' });
  }
  return found;
}
function lineOf(text, name) {
  const lines = text.split('\n'), q = name.toLowerCase();
  const exact = lines.findIndex(l => l.toLowerCase().includes(`"${q}"`) || l.toLowerCase().includes(`/${q}"`));
  const loose = exact >= 0 ? exact : lines.findIndex(l => l.toLowerCase().includes(q));
  return loose >= 0 ? loose + 1 : 1;
}

// ---------------------------------------------------------------- ignore list: "ID [until YYYY-MM-DD] [# reason]"
async function loadIgnores() {
  const list = [];
  for (const id of opts.ignore.split(/[\s,]+/).filter(Boolean)) list.push({ id: id.toUpperCase(), until: null, source: 'input' });
  try {
    const text = await fs.readFile(path.join(opts.root, opts.ignoreFile), 'utf8');
    for (const raw of text.split('\n')) {
      const line = raw.replace(/#.*$/, '').trim(); if (!line) continue;
      const m = /^(\S+)(?:\s+until\s+(\d{4}-\d{2}-\d{2}))?/i.exec(line);
      if (m) list.push({ id: m[1].toUpperCase(), until: m[2] || null, reason: (/#\s*(.*)$/.exec(raw) || [])[1] || '', source: opts.ignoreFile });
    }
  } catch { /* no ignore file */ }
  return list;
}

// ---------------------------------------------------------------- main
const started = Date.now();
const files = await discover(opts.root);
const ignores = await loadIgnores();
const today = new Date().toISOString().slice(0, 10);
const expired = ignores.filter(x => x.until && x.until < today);

const pkgs = [], images = [], texts = new Map();
for (const f of files) {
  const stat = await fs.stat(f.full);
  if (stat.size > 25e6) { log(`Skipping ${f.rel}: larger than 25 MB`); continue; }
  const text = await fs.readFile(f.full, 'utf8');
  texts.set(f.rel, text);
  if (f.kind === 'lock') for (const p of T.parseLock(f.rel, text)) pkgs.push({ ...p, file: f.rel });
  else for (const im of T.parseImages(f.rel, text)) images.push({ ...im, file: f.rel });
}

let catalog, compromises, results = [], runtimeResults = [];
if (opts.api === DEFAULT_API) {
  const ok = await fetch(`${DEFAULT_API}/api/v1/health.json`, { signal: AbortSignal.timeout(8000) }).then(r => r.ok).catch(() => false);
  if (!ok) { log(`${DEFAULT_API} did not answer; using ${FALLBACK_API}`); opts.api = FALLBACK_API; }
}
log(`Threatline check ${VERSION}: ${files.length} files, ${pkgs.length} package versions, ${images.length} images. Data from ${opts.api}`);
try {
  [catalog, compromises] = await Promise.all([get('api/v1/catalog.json'), get('api/v1/compromises.json', { optional: true })]);
} catch (err) {
  const msg = `Could not reach Threatline (${err.message}).`;
  if (opts.onApiError === 'fail') die(msg);
  console.log(inActions ? `::warning title=Threatline check::${esc(msg + ' Nothing was checked.')}` : msg);
  await writeOutputs({ failed: false, findings: [], skipped: true });
  process.exit(0);
}
const byId = new Map();
for (const r of catalog.records || []) { byId.set(r.id, r); for (const a of r.aliases || []) if (!byId.has(a)) byId.set(a, r); }
const SEV = { Critical: 4, High: 3, Medium: 2, Low: 1 };
const sevOf = (h, r) => SEV[h.severity] || SEV[r?.severity] || 0;
// Known exploited: CISA KEV, CISA's exploitation assessment, or exploitation reported by at least two independent outlets.
const reportedOf = r => !!(r?.signals && (r.signals.exploited || r.signals.zero_day) && r.signals.outlets >= 2);
const exploitedOf = r => !!(r && (r.kev || r.ssvc === 'active' || reportedOf(r)));
const rank = (a, b) => {
  const ra = a.cve && byId.get(a.cve), rb = b.cve && byId.get(b.cve);
  return (b.mal ? 1 : 0) - (a.mal ? 1 : 0) || exploitedOf(rb) - exploitedOf(ra) || sevOf(b, rb) - sevOf(a, ra) || (rb?.epss ?? 0) - (ra?.epss ?? 0);
};

// Packages: one lookup per ecosystem, matched locally. Each file's packages are matched separately so findings point at the file.
const indexes = new Map();
const loadIndex = eco => { if (!indexes.has(eco)) indexes.set(eco, get(`api/v1/packages/${eco}.json`, { optional: true })); return indexes.get(eco); };
const uniq = new Map();
for (const p of pkgs) { const k = `${p.eco}|${p.name.toLowerCase()}|${p.version}`; if (!uniq.has(k)) uniq.set(k, { ...p, files: [] }); uniq.get(k).files.push(p.file); }
results = await T.matchPackages([...uniq.values()], { loadIndex, compromises: compromises?.compromises || [], rank });

// Images: pinned versions are checked against the full CVE records of matching products.
const recordCache = new Map();
const fullRecord = id => { if (!recordCache.has(id)) recordCache.set(id, get(`api/v1/cve/${encodeURIComponent(id)}.json`, { optional: true }).then(d => d?.record || null)); return recordCache.get(id); };
for (const im of images) {
  if (!im.pinned) { runtimeResults.push({ ...im, eco: 'image', unpinned: true, hits: [] }); continue; }
  const rows = T.runtimeCandidates(catalog.records || [], im.name);
  const recs = await pool(rows, 8, r => fullRecord(r.id));
  const hits = [];
  rows.forEach((r, i) => { const hit = recs[i] && T.runtimeHit(im.name, im.version, recs[i]); if (hit) hits.push({ id: r.id, cve: r.id, summary: r.summary, severity: r.severity, fix: hit.fix }); });
  hits.sort(rank);
  const fixes = hits.map(h => h.fix);
  runtimeResults.push({ ...im, eco: 'image', files: [im.file], hits, target: fixes.includes(null) || !fixes.length ? null : fixes.sort(T.vcmp).slice(-1)[0] });
}

// ---------------------------------------------------------------- findings and policy
const site = opts.api;
const findings = [];
for (const r of [...results, ...runtimeResults]) {
  for (const h of r.hits) {
    const rec = h.cve ? byId.get(h.cve) : byId.get(h.id);
    const ids = [h.id, h.cve, h.compromise, ...(rec?.aliases || []), rec?.id].filter(Boolean).map(x => String(x).toUpperCase());
    const ign = ignores.find(x => ids.includes(x.id) && !(x.until && x.until < today));
    const tier = h.mal ? 'malicious' : exploitedOf(rec) ? 'exploited' : sevOf(h, rec) >= 4 ? 'critical' : sevOf(h, rec) >= 3 ? 'high' : 'any';
    const fixable = !!h.fix;
    const fails = !ign && LEVELS[tier] >= LEVELS[opts.failOn] && (h.mal || fixable || opts.failWithoutFix);
    const url = h.compromise ? `${site}/#supply/${h.compromise}` : rec ? `${site}/cve/${rec.id}` : `https://osv.dev/vulnerability/${encodeURIComponent(h.id)}`;
    const reported = !rec?.kev && rec?.ssvc !== 'active' && reportedOf(rec) ? rec.signals.outlets : 0;
    findings.push({
      file: r.files?.[0] || r.file, files: r.files || [r.file], line: r.line || lineOf(texts.get(r.files?.[0] || r.file) || '', r.name),
      eco: r.eco, name: r.name, version: r.version, image: r.image, id: rec?.id || h.cve || h.id, advisory: h.id, summary: h.summary || rec?.summary || '',
      severity: h.mal ? 'Critical' : (h.severity || rec?.severity || null), kev: !!rec?.kev, kev_added: rec?.kev_added || null, ssvc: rec?.ssvc || null,
      epss: typeof rec?.epss === 'number' ? rec.epss : null, reported_by_outlets: reported, malicious: !!h.mal, compromise: h.compromise || null,
      fix: h.fix || null, target: r.target || null, tier, fails, ignored: ign ? { id: ign.id, until: ign.until, source: ign.source } : null, url,
    });
  }
}
findings.sort((a, b) => b.fails - a.fails || LEVELS[b.tier] - LEVELS[a.tier] || (b.epss ?? 0) - (a.epss ?? 0));
const failing = findings.filter(f => f.fails);
const unpinned = runtimeResults.filter(r => r.unpinned);

// ---------------------------------------------------------------- report
const ECO = { ...T.ECO, image: 'image' };
const RULE = { malicious: 'malicious releases', exploited: 'malicious releases and known exploited vulnerabilities', critical: 'malicious, known exploited and critical issues', high: 'malicious, known exploited, critical and high issues', any: 'any known vulnerability', none: 'nothing (report only)' };
const TIER = { malicious: 'Malicious release', exploited: 'Known exploited', critical: 'Critical', high: 'High', any: 'Lower' };
const tierLabel = f => (f.tier === 'any' ? f.severity || 'Unrated' : TIER[f.tier]);
const fmtDay = d => (d ? new Date(d).toUTCString().slice(5, 16) : '');
function evidence(f) {
  if (f.malicious) return 'Release taken over by attackers';
  if (f.kev) return `CISA KEV${f.kev_added ? `, ${fmtDay(f.kev_added)}` : ''}`;
  if (f.ssvc === 'active') return 'CISA: exploitation active';
  if (f.reported_by_outlets) return `Exploitation reported by ${f.reported_by_outlets} outlets`;
  return f.epss !== null ? `EPSS ${(f.epss * 100).toFixed(f.epss < 0.1 ? 1 : 0)}%` : '';
}
function action(f) { return f.malicious ? 'Remove it, rotate credentials' : f.fix ? `Upgrade to ${f.fix}` : 'No fix yet'; }
function row(f) {
  const where = f.files.slice(0, 2).map(x => `\`${x}\``).join(', ') + (f.files.length > 2 ? ` +${f.files.length - 2}` : '');
  return `| ${tierLabel(f)} | \`${f.name} ${f.version}\` ${ECO[f.eco] || f.eco}<br>${where} | [${f.malicious ? 'Supply chain' : f.id}](${f.url}) ${String(f.summary).replace(/\|/g, '\\|').slice(0, 120)} | ${evidence(f)} | ${action(f)}${f.ignored ? ` (ignored${f.ignored.until ? ` until ${f.ignored.until}` : ''})` : ''} |`;
}
function markdown() {
  const head = failing.length ? `### Threatline: ${failing.length === 1 ? '1 issue blocks' : `${failing.length} issues block`} this change` : findings.length ? `### Threatline: nothing blocking, ${findings.length === 1 ? '1 issue' : `${findings.length} issues`} to review` : '### Threatline: no known issues';
  const out = ['<!-- threatline-check -->', head, ''];
  const shown = failing.length ? failing : findings.filter(f => !f.ignored).slice(0, 15);
  if (shown.length) {
    out.push('| | Package | Issue | Evidence | Action |', '|---|---|---|---|---|', ...shown.slice(0, 40).map(row), '');
    if (failing.length && failing.some(f => f.malicious)) out.push('> A malicious release is not fixed by upgrading. Remove it, treat machines that installed it as compromised, and rotate the credentials they could reach.', '');
  }
  const rest = findings.filter(f => !shown.includes(f));
  if (rest.length) out.push(`<details><summary>${rest.length} more below the fail level or ignored</summary>`, '', '| | Package | Issue | Evidence | Action |', '|---|---|---|---|---|', ...rest.slice(0, 80).map(row), '', '</details>', '');
  if (unpinned.length) out.push(`Not checked: ${unpinned.map(u => `\`${u.image}\``).join(', ')} use floating tags. Pin a full version (for example \`php:8.3.36\`) to check them.`, '');
  if (expired.length) out.push(`Expired ignores, no longer applied: ${expired.map(x => `${x.id} (until ${x.until})`).join(', ')}.`, '');
  out.push(`<sub>Checked ${uniq.size} package versions in ${files.filter(f => f.kind === 'lock').length} files and ${images.length} images against [Threatline](${site}) data from ${fmtDay(catalog.generated_at)} ${String(catalog.generated_at || '').slice(11, 16)} UTC. Fails on ${RULE[opts.failOn]}${opts.failWithoutFix ? ', with or without a fix' : ' that have a fix'}. Your dependency list never left this runner.</sub>`);
  return out.join('\n');
}

async function writeOutputs({ failed, findings: list, skipped = false }) {
  if (env.GITHUB_OUTPUT) {
    const lines = [`failed=${failed}`, `findings=${list.length}`, `exploited=${list.filter(f => f.tier === 'exploited').length}`, `malicious=${list.filter(f => f.malicious).length}`, `skipped=${skipped}`];
    if (opts.report) lines.push(`report=${opts.report}`);
    await fs.appendFile(env.GITHUB_OUTPUT, lines.join('\n') + '\n');
  }
}

const md = markdown();
if (opts.json) console.log(JSON.stringify({ version: VERSION, data_as_of: catalog.generated_at, fail_on: opts.failOn, failed: failing.length > 0, files: files.map(f => f.rel), findings, unpinned_images: unpinned.map(u => u.image) }, null, 2));
else {
  for (const f of findings.slice(0, 60)) log(`${f.fails ? 'FAIL' : f.ignored ? 'IGN ' : 'warn'}  ${f.name} ${f.version} (${ECO[f.eco] || f.eco})  ${f.malicious ? 'malicious release' : f.id}  ${tierLabel(f)}${evidence(f) ? ', ' + evidence(f) : ''}  ${action(f)}  [${f.files[0]}]`);
  if (findings.length > 60) log(`... and ${findings.length - 60} more`);
  for (const u of unpinned) log(`skip  ${u.image} in ${u.file}: floating tag, pin a full version to check it`);
  log(failing.length ? `\n${failing.length} blocking ${failing.length === 1 ? 'issue' : 'issues'} (fail-on: ${opts.failOn}).` : `\nNo blocking issues (fail-on: ${opts.failOn}). ${findings.length} to review.`);
}
if (opts.report) await fs.writeFile(opts.report, md + '\n');
if (env.GITHUB_STEP_SUMMARY) await fs.appendFile(env.GITHUB_STEP_SUMMARY, md + '\n');

if (inActions) {
  let n = 0;
  for (const f of findings.filter(x => !x.ignored)) {
    if (n++ >= 40) break;
    const level = f.fails ? 'error' : 'warning';
    const title = `${tierLabel(f)}: ${f.name} ${f.version}`;
    console.log(`::${level} file=${escProp(f.file)},line=${f.line},title=${escProp(title)}::${esc(`${f.malicious ? 'Malicious release' : f.id}: ${f.summary}. ${action(f)}. ${f.url}`)}`);
  }
  for (const x of expired) console.log(`::warning title=Threatline ignore expired::${esc(`${x.id} was ignored until ${x.until}; it is checked again.`)}`);
}

// SARIF for GitHub code scanning (upload with github/codeql-action/upload-sarif).
if (opts.sarif) {
  const rules = new Map();
  for (const f of findings) if (!rules.has(f.id)) rules.set(f.id, { id: f.id, shortDescription: { text: String(f.summary || f.id).slice(0, 200) }, helpUri: f.url, properties: { 'security-severity': String({ malicious: 10, exploited: 9.5, critical: 9, high: 7.5, any: 5 }[f.tier]), tags: ['security', 'dependency'] } });
  const sarif = { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs: [{ tool: { driver: { name: 'Threatline', version: VERSION, informationUri: site, rules: [...rules.values()] } },
    results: findings.filter(f => !f.ignored).map(f => ({ ruleId: f.id, level: f.fails ? 'error' : 'warning', message: { text: `${f.name} ${f.version}: ${f.summary}. ${action(f)}.` },
      locations: f.files.map(file => ({ physicalLocation: { artifactLocation: { uri: file }, region: { startLine: file === f.file ? f.line : lineOf(texts.get(file) || '', f.name) } } })) })) }] };
  await fs.writeFile(opts.sarif, JSON.stringify(sarif, null, 1));
}

// Pull request comment: one comment, updated in place. Posted when something is found, or to clear an earlier one.
if (inActions && opts.comment && opts.token && /^pull_request/.test(env.GITHUB_EVENT_NAME || '')) {
  try {
    const event = JSON.parse(await fs.readFile(env.GITHUB_EVENT_PATH, 'utf8'));
    const pr = event.pull_request?.number, repo = env.GITHUB_REPOSITORY, apiUrl = env.GITHUB_API_URL || 'https://api.github.com';
    const gh = (method, url, body) => fetch(url, { method, headers: { Authorization: `Bearer ${opts.token}`, Accept: 'application/vnd.github+json', 'User-Agent': `threatline-check/${VERSION}`, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    let existing = null;
    for (let page = 1; page <= 10 && !existing; page++) {
      const res = await gh('GET', `${apiUrl}/repos/${repo}/issues/${pr}/comments?per_page=100&page=${page}`);
      if (!res.ok) throw new Error(`listing comments returned ${res.status}`);
      const list = await res.json();
      existing = list.find(c => String(c.body || '').startsWith('<!-- threatline-check -->'));
      if (list.length < 100) break;
    }
    if (findings.length || existing) {
      const res = existing ? await gh('PATCH', `${apiUrl}/repos/${repo}/issues/comments/${existing.id}`, { body: md }) : await gh('POST', `${apiUrl}/repos/${repo}/issues/${pr}/comments`, { body: md });
      if (!res.ok) throw new Error(`${existing ? 'updating' : 'posting'} the comment returned ${res.status}`);
    }
  } catch (err) {
    console.log(`::warning title=Threatline comment::${esc(`Could not comment on the pull request (${err.message}). Give the workflow "pull-requests: write" permission, or set comment: false.`)}`);
  }
}

await writeOutputs({ failed: failing.length > 0, findings });
if (!opts.json) log(`Done in ${((Date.now() - started) / 1000).toFixed(1)}s.`);
process.exit(failing.length ? 1 : 0);
