/* Threatline stack check core. One copy of the parsing and matching rules, used by the web app
   (bundled ahead of app.js) and by the Threatline GitHub Action (action/), so both always agree.
   No dependencies; runs in browsers and Node 18+. Sets globalThis.ThreatlineStack. */
(function (root) {
  'use strict';

  const ECO = { npm: 'npm', pypi: 'PyPI', go: 'Go', cargo: 'crates.io', gem: 'RubyGems', composer: 'Packagist', maven: 'Maven', nuget: 'NuGet' };
  const PURL_ECO = { npm: 'npm', pypi: 'pypi', golang: 'go', cargo: 'cargo', gem: 'gem', composer: 'composer', maven: 'maven', nuget: 'nuget' };

  // ---- versions
  const VORDER = { dev: -4, alpha: -3, a: -3, beta: -2, b: -2, pre: -1.5, preview: -1.5, m: -1.5, milestone: -1.5, rc: -1, cr: -1, c: -1, snapshot: -0.5, final: 0, ga: 0, release: 0, sp: 1, post: 1, patch: 1, p: 1 };
  function vparts(v) { return String(v).trim().replace(/^v(?=\d)/i, '').replace(/\+.*$/, '').toLowerCase().match(/\d+|[a-z]+/g) || []; }
  // Ecosystem-neutral version order: numbers numerically, pre-release words below a release, post-release words above.
  function vcmp(a, b) {
    if (a === b) return 0;
    if (a === '0') return -1;
    if (b === '0') return 1;
    const A = vparts(a), B = vparts(b);
    for (let i = 0; i < Math.max(A.length, B.length); i++) {
      const x = A[i], y = B[i];
      if (x === y) continue;
      if (x === undefined) return /^\d/.test(y) ? (+y === 0 ? 0 : -1) : ((VORDER[y] ?? -1) < 0 ? 1 : -1);
      if (y === undefined) return /^\d/.test(x) ? (+x === 0 ? 0 : 1) : ((VORDER[x] ?? -1) < 0 ? -1 : 1);
      const nx = /^\d/.test(x), ny = /^\d/.test(y);
      if (nx && ny) { if (+x !== +y) return +x < +y ? -1 : 1; continue; }
      if (nx !== ny) return nx ? ((VORDER[y] ?? -1) < 0 ? 1 : -1) : ((VORDER[x] ?? -1) < 0 ? -1 : 1);
      const ox = VORDER[x] ?? -1, oy = VORDER[y] ?? -1;
      if (ox !== oy) return ox < oy ? -1 : 1;
      if (x !== y) return x < y ? -1 : 1;
    }
    return 0;
  }
  function fixFor(v, adv) { const f = (adv.ranges || []).filter(([i, fx]) => fx && vcmp(v, i) >= 0 && vcmp(v, fx) < 0).map(r => r[1]); return f.sort(vcmp)[0] || null; }
  // An advisory from a package index: explicit versions, or [introduced, fixed, last_affected] ranges.
  function inRanges(v, adv) {
    if ((adv.versions || []).includes(v)) return { hit: true, fix: fixFor(v, adv) };
    for (const [intro, fixed, last] of adv.ranges || []) {
      if (vcmp(v, intro) < 0) continue;
      if (fixed ? vcmp(v, fixed) < 0 : last ? vcmp(v, last) <= 0 : true) return { hit: true, fix: fixed || null };
    }
    return { hit: false };
  }
  // A CVE record's affected_ranges entry (CVE List or GitHub style). Returns the fixed version, 'a later release', or null.
  // ">= 8.3.0, < 8.3.8" (GitHub style, also found in CVE List version fields). Returns the fix, 'a later release', or null.
  function rangeStrHit(ver, str) {
    const ok = String(str).split(',').every(c => { const m = /^\s*(>=|<=|>|<|=)\s*(\S+)/.exec(c); if (!m) return false; const k = vcmp(ver, m[2]); return { '>=': k >= 0, '<=': k <= 0, '>': k > 0, '<': k < 0, '=': k === 0 }[m[1]]; });
    if (!ok) return null;
    const m = /<\s*([^\s,]+)/.exec(str);
    return m && !/<=/.test(str) ? m[1] : 'a later release';
  }
  function cveRangeHit(ver, entry) {
    for (const v of entry.versions || []) {
      if (typeof v !== 'object' || v.status !== 'affected') continue;
      if (/^\s*[<>=]/.test(String(v.version || ''))) { const hit = rangeStrHit(ver, v.version); if (hit) return hit; continue; }
      const lo = String(v.version || '0'), star = lo.includes('*') ? lo.replace(/\.?\*.*$/, '') : null;
      if (star && !(ver === star || ver.startsWith(star + '.'))) continue;
      if (!star && lo !== '0' && vcmp(ver, lo) < 0) continue;
      if (v.lessThan && v.lessThan !== '*') { if (vcmp(ver, v.lessThan) < 0) return v.lessThan; continue; }
      if (v.lessThanOrEqual && v.lessThanOrEqual !== '*') { if (vcmp(ver, v.lessThanOrEqual) <= 0) return 'a later release'; continue; }
      if (!v.lessThan && !v.lessThanOrEqual && !star && lo === ver) return 'a later release';
    }
    if (entry.range) return rangeStrHit(ver, entry.range);  // GitHub style: ">= 8.3.0, < 8.3.8"
    if ((entry.ranges || []).length) {  // OSV events: introduced / fixed / last_affected
      for (const r of entry.ranges) {
        if (r.type === 'GIT') continue;
        let start = null;
        for (const e of r.events || []) {
          if ('introduced' in e) start = e.introduced;
          else if ('fixed' in e) { if (vcmp(ver, start || '0') >= 0 && vcmp(ver, e.fixed) < 0) return e.fixed; start = null; }
          else if ('last_affected' in e) { if (vcmp(ver, start || '0') >= 0 && vcmp(ver, e.last_affected) <= 0) return 'a later release'; start = null; }
        }
        if (start !== null && vcmp(ver, start) >= 0) return 'a later release';
      }
    }
    return null;
  }
  // Whether an entry carries anything we can evaluate.
  const evaluable = e => (e.versions || []).some(v => typeof v === 'object' && v.status === 'affected') || !!e.range || (e.ranges || []).some(r => r.type !== 'GIT');
  // "Am I affected?" for one record: per product, affected (with the fix) or not, or null when nothing can be evaluated.
  function recordHit(rec, version, product) {
    const ver = String(version || '').trim().replace(/^v(?=\d)/i, '');
    if (!ver) return null;
    const entries = (rec.affected_ranges || []).filter(evaluable).filter(e => !product || String(e.product || e.package?.name || '').toLowerCase() === product.toLowerCase());
    if (!entries.length) return null;
    for (const e of entries) { const fix = cveRangeHit(ver, e); if (fix) return { affected: true, fix: fix === 'a later release' ? null : fix, source: e.source || null }; }
    // Not in any listed range. CVE records often list only the release lines that got a fix, so a version older than
    // every listed range (an end-of-life line) is not evidence of safety. Only "newer than every fix" is reassuring.
    const lows = [], highs = [];
    for (const e of entries) for (const v of e.versions || []) {
      if (typeof v !== 'object' || v.status !== 'affected') continue;
      const raw = String(v.version || '');
      const lo = /^\s*[<>=]/.test(raw) ? (/>=?\s*([^\s,]+)/.exec(raw) || [])[1] : raw.replace(/\.?\*.*$/, '');
      const hi = v.lessThan || v.lessThanOrEqual || (/<=?\s*([^\s,]+)/.exec(raw) || [])[1];
      if (lo && lo !== '0') lows.push(lo);
      if (hi && hi !== '*') highs.push(hi);
    }
    if (highs.length && highs.every(h => vcmp(ver, h) >= 0)) return { affected: false, status: 'newer' };
    // At or past the fix on its own release line (8.3.36 for the 8.3 line).
    const line = v => String(v).replace(/^v/i, '').split(/[.-]/).slice(0, 2).join('.');
    if (highs.some(h => line(h) === line(ver) && vcmp(ver, h) >= 0)) return { affected: false, status: 'fixed' };
    if (lows.length && lows.every(l => vcmp(ver, l) < 0 && !ver.startsWith(l + '.'))) return { affected: false, status: 'older' };
    return { affected: false, status: entries.some(e => (e.ranges || []).length || e.range) ? 'outside' : 'unlisted' };
  }
  const recordProducts = rec => [...new Set((rec.affected_ranges || []).filter(evaluable).map(e => e.product || e.package?.name).filter(Boolean))];

  // ---- lockfiles and SBOMs: each returns [{eco, name, version}]
  const clean = v => String(v || '').trim().replace(/^[=v]+(?=\d)/, '').replace(/^==/, '');
  // File names the parsers understand (go.sum is left to go.mod, which holds the selected versions).
  const LOCKFILE_RE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|pipfile\.lock|poetry\.lock|uv\.lock|cargo\.lock|gemfile\.lock|go\.mod|(requirements|constraints)[^/]*\.txt|[^/]*\.cdx\.json|[^/]*\.spdx\.json|bom\.json|sbom[^/]*\.json)$/i;
  function parseLock(name, text) {
    const n = name.toLowerCase(), out = [], add = (eco, pkg, ver) => { ver = clean(ver); if (pkg && ver && /\d/.test(ver)) out.push({ eco, name: pkg.trim(), version: ver }); };
    const asJSON = () => { try { return JSON.parse(text); } catch { return null; } };
    if (n.endsWith('package-lock.json') || n.endsWith('npm-shrinkwrap.json')) {
      const j = asJSON() || {};
      for (const [k, v] of Object.entries(j.packages || {})) if (k && v.version && !v.link) add('npm', v.name || k.replace(/^.*node_modules\//, ''), v.version);
      const walk = deps => { for (const [k, v] of Object.entries(deps || {})) { add('npm', k, v.version); walk(v.dependencies); } };
      if (!j.packages) walk(j.dependencies);
    } else if (n.endsWith('yarn.lock')) {
      let cur = null;
      for (const line of text.split('\n')) {
        if (/^\S/.test(line) && !line.startsWith('#')) { const m = /^"?(@?[^@"\s]+)@/.exec(line); cur = m ? m[1] : null; }
        else { const m = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line); if (m && cur) { add('npm', cur, m[1]); cur = null; } }
      }
    } else if (n.endsWith('pnpm-lock.yaml')) {
      for (const m of text.matchAll(/^\s{2}'?\/?((?:@[^/\s]+\/)?[^@\s/:']+)@(\d[^\s(:']*)/gm)) add('npm', m[1], m[2]);
    } else if (n.endsWith('composer.lock')) {
      const j = asJSON() || {};
      for (const p of [...(j.packages || []), ...(j['packages-dev'] || [])]) add('composer', p.name, p.version);
    } else if (n.endsWith('pipfile.lock')) {
      const j = asJSON() || {};
      for (const sec of ['default', 'develop']) for (const [k, v] of Object.entries(j[sec] || {})) add('pypi', k, (v.version || '').replace(/^==/, ''));
    } else if (n.endsWith('poetry.lock') || n.endsWith('uv.lock') || n.endsWith('cargo.lock')) {
      const eco = n.endsWith('cargo.lock') ? 'cargo' : 'pypi';
      for (const block of text.split(/\[\[package\]\]/).slice(1)) {
        const nm = /^name\s*=\s*"([^"]+)"/m.exec(block), vr = /^version\s*=\s*"([^"]+)"/m.exec(block);
        if (nm && vr) add(eco, nm[1], vr[1]);
      }
    } else if (n.endsWith('gemfile.lock')) {
      let inSpecs = false;
      for (const line of text.split('\n')) {
        if (/^\s{2}specs:/.test(line)) { inSpecs = true; continue; }
        if (/^\S/.test(line)) inSpecs = false;
        const m = inSpecs && /^\s{4}([^\s(]+) \(([^)]+)\)/.exec(line);
        if (m) add('gem', m[1], m[2].split('-')[0]);
      }
    } else if (n.endsWith('go.sum') || n.endsWith('go.mod')) {
      for (const m of text.matchAll(/^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}\/[^\s]+)\s+(v[^\s/]+?)(?:\/go\.mod)?(?:\s|$)/gim)) add('go', m[1], m[2].replace(/\+incompatible$/, ''));
    } else if (/requirements.*\.txt$|constraints.*\.txt$/.test(n)) {
      for (const m of text.matchAll(/^\s*([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)/gm)) add('pypi', m[1], m[2]);
    } else if (n.endsWith('.json') && /bomformat|spdxversion|"purl"|referencelocator/i.test(text)) {
      const j = asJSON() || {};
      const purls = [...(j.components || []).map(c => c.purl), ...(j.packages || []).flatMap(p => (p.externalRefs || []).filter(r => r.referenceType === 'purl').map(r => r.referenceLocator))];
      for (const pu of purls.filter(Boolean)) {
        const m = /^pkg:([a-z]+)\/(.+)@([^?#]+)/.exec(decodeURIComponent(pu)); if (!m || !PURL_ECO[m[1]]) continue;
        const nm = m[1] === 'maven' ? m[2].replace('/', ':') : m[2];
        add(PURL_ECO[m[1]], nm, m[3]);
      }
    }
    const seen = new Set();
    return out.filter(p => { const k = `${p.eco}|${p.name.toLowerCase()}|${p.version}`; if (seen.has(k)) return false; seen.add(k); return true; });
  }

  // Free text: "npm lodash 4.17.20", "lodash@4.17.20" (npm), "pypi django 4.2.1", or "php 8.3.30" (anything else: a product we track).
  function parseManual(text) {
    const pkgs = [], runtimes = [];
    for (const raw of text.split(/[\n,;]+/)) {
      const line = raw.trim(); if (!line) continue;
      let m = /^(npm|pypi|go|cargo|gem|composer|maven|nuget)\s+(\S+)\s+v?(\d\S*)$/i.exec(line);
      if (m) { pkgs.push({ eco: m[1].toLowerCase(), name: m[2], version: clean(m[3]) }); continue; }
      m = /^(@?[^\s@]+)@(\d\S*)$/.exec(line);
      if (m) { pkgs.push({ eco: 'npm', name: m[1], version: m[2] }); continue; }
      m = /^(.+?)\s+v?(\d[\w.\-]*)$/.exec(line);
      if (m) runtimes.push({ name: m[1].trim(), version: m[2] });
    }
    return { pkgs, runtimes };
  }

  // ---- container images: official images whose tag is the product version
  const IMAGE_PRODUCTS = {
    php: 'php', node: 'node', python: 'python', ruby: 'ruby', golang: 'go', nginx: 'nginx', httpd: 'http server', tomcat: 'tomcat',
    redis: 'redis', postgres: 'postgresql', mysql: 'mysql', mariadb: 'mariadb', mongo: 'mongodb', memcached: 'memcached', rabbitmq: 'rabbitmq',
    haproxy: 'haproxy', traefik: 'traefik', caddy: 'caddy', wordpress: 'wordpress', drupal: 'drupal', nextcloud: 'nextcloud', ghost: 'ghost',
    'gitlab/gitlab-ce': 'gitlab', 'gitlab/gitlab-ee': 'gitlab', 'jenkins/jenkins': 'jenkins', 'grafana/grafana': 'grafana',
    'hashicorp/vault': 'vault', 'hashicorp/consul': 'consul', 'quay.io/keycloak/keycloak': 'keycloak', 'keycloak/keycloak': 'keycloak',
    elasticsearch: 'elasticsearch', 'docker.elastic.co/elasticsearch/elasticsearch': 'elasticsearch', 'minio/minio': 'minio', 'apache/airflow': 'airflow',
  };
  // Dockerfile FROM lines and compose "image:" lines -> [{name, version, image, line, pinned}]. Floating tags (php:8.3) are
  // reported as unpinned rather than guessed, since the patch release they pull changes over time.
  function parseImages(name, text) {
    const out = [], lines = String(text).split('\n');
    const isCompose = /(^|\/)(docker-)?compose[^/]*\.ya?ml$/i.test(name);
    lines.forEach((line, i) => {
      const m = isCompose ? /^\s*image:\s*["']?([^\s"'#]+)/.exec(line) : /^\s*FROM\s+(?:--platform=\S+\s+)?([^\s#]+)/i.exec(line);
      if (!m) return;
      const ref = m[1].replace(/@sha256:[a-f0-9]+$/i, '');
      if (/\$\{?/.test(ref)) return;
      const colon = ref.lastIndexOf(':'), slash = ref.lastIndexOf('/');
      const repo = (colon > slash ? ref.slice(0, colon) : ref).replace(/^(docker\.io\/)?(library\/)?/, '');
      const tag = colon > slash ? ref.slice(colon + 1) : 'latest';
      const product = IMAGE_PRODUCTS[repo];
      if (!product) return;
      const vm = /^v?(\d+(?:\.\d+)*)/.exec(tag);
      const version = vm ? vm[1] : null;
      out.push({ name: product, version, image: ref, line: i + 1, pinned: !!version && version.split('.').length >= 3 });
    });
    return out;
  }
  const IMAGE_RE = /(^|\/)([^/]*\.)?dockerfile$|(^|\/)dockerfile[^/]*$|(^|\/)(docker-)?compose[^/]*\.ya?ml$/i;

  // ---- matching
  const normName = (eco, n) => n.toLowerCase().replace(/[-_.]+/g, eco === 'pypi' ? '-' : '$&');
  // pkgs: [{eco, name, version, ...}]. loadIndex(eco) resolves to {packages: {name: [advisory]}} or null.
  // compromises: curated entries from /api/v1/compromises.json (they can be ahead of OSV's malicious-package reports).
  // rank(a, b) orders the hits of one package, most urgent first.
  async function matchPackages(pkgs, { loadIndex, compromises = [], rank = () => 0 }) {
    const results = [];
    const curated = new Map();
    for (const c of compromises) for (const p of c.packages || []) for (const v of p.versions) curated.set(`${p.ecosystem}|${p.name.toLowerCase()}|${v}`, c);
    for (const eco of [...new Set(pkgs.map(p => p.eco))]) {
      const idx = await loadIndex(eco);
      const byLower = idx ? new Map(Object.keys(idx.packages).map(k => [normName(eco, k), k])) : new Map();
      for (const p of pkgs.filter(x => x.eco === eco)) {
        const key = idx && (idx.packages[p.name] ? p.name : byLower.get(normName(eco, p.name)));
        const hits = [];
        for (const a of key ? idx.packages[key] : []) { const m = inRanges(p.version, a); if (m.hit) hits.push({ ...a, cve: (a.cve || [])[0] || null, fix: m.fix }); }
        const c = curated.get(`${eco}|${p.name.toLowerCase()}|${p.version}`);
        if (c && !hits.some(h => h.mal)) hits.push({ id: c.id, mal: true, summary: c.title, severity: 'Critical', fix: null, compromise: c.id });
        else if (c) for (const h of hits) if (h.mal) h.compromise = c.id;
        hits.sort(rank);
        const fixes = hits.filter(h => !h.mal).map(h => h.fix);
        const target = fixes.includes(null) || !fixes.length ? null : fixes.sort(vcmp).slice(-1)[0];
        results.push({ ...p, indexed: !!idx || !!c, hits, target, mal: hits.some(h => h.mal), unfixed: hits.filter(h => !h.fix && !h.mal).length });
      }
    }
    return results;
  }
  // Catalog rows that could describe a product name such as "php" or "gitlab".
  function runtimeCandidates(rows, name, limit = 120) {
    const q = name.toLowerCase();
    return rows.filter(r => { const p = (r.product || '').toLowerCase(), v = (r.vendor || '').toLowerCase(); return p === q || `${v} ${p}`.includes(q) && (p.split(/\s+/).includes(q) || p.startsWith(q + ' ') || v === q); }).slice(0, limit);
  }
  // Test one runtime version against full records (as fetched from /api/v1/cve/{id}.json).
  function runtimeHit(name, version, rec) {
    const q = name.toLowerCase();
    for (const e of rec.affected_ranges || []) {
      const nm = String(e.product || e.package?.name || '').toLowerCase();
      if (nm && !nm.includes(q)) continue;
      const fix = cveRangeHit(version, e);
      if (fix) return { fix: fix === 'a later release' ? null : fix };
    }
    return null;
  }

  // ---- the command that moves a package to a fixed version, per ecosystem
  const ECO_KEY = { npm: 'npm', pypi: 'pypi', PyPI: 'pypi', go: 'go', Go: 'go', cargo: 'cargo', 'crates.io': 'cargo', gem: 'gem', RubyGems: 'gem', composer: 'composer', Packagist: 'composer', maven: 'maven', Maven: 'maven', nuget: 'nuget', NuGet: 'nuget' };
  function upgradeCommand(eco, name, version) {
    const k = ECO_KEY[eco], v = String(version || '').trim();
    if (!k || !name || !v || /\s/.test(name + v)) return null;
    switch (k) {
      case 'npm': return `npm install ${name}@${v}`;
      case 'pypi': return `pip install "${name}>=${v}"`;
      case 'go': return `go get ${name}@${v.startsWith('v') ? v : 'v' + v}`;
      case 'cargo': return `cargo update -p ${name} --precise ${v}`;
      case 'gem': return `bundle update ${name} --conservative  # needs ${v} or later`;
      case 'composer': return `composer require "${name}:^${v}"`;
      case 'nuget': return `dotnet add package ${name} --version ${v}`;
      case 'maven': { const [g, a] = name.split(':'); return a ? `<dependency><groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version></dependency>` : null; }
    }
    return null;
  }

  // ---- a record's timeline: when it was published, first reported, first reported exploited, when exploit code
  // and WAF rules appeared, and when CISA listed it. rec is a full record, sig its signal entry, first its first
  // sightings (signals.json "firsts"). Each event names its source.
  function timeline(rec, sig, first) {
    const ev = [], add = (at, kind, label, source, url) => { if (at && Number.isFinite(Date.parse(at))) ev.push({ at, kind, label, source, url }); };
    const cveUrl = `https://www.cve.org/CVERecord?id=${encodeURIComponent(rec.id)}`;
    add(rec.published_at, 'published', 'Published', /^CVE-/.test(rec.id) ? 'CVE List' : 'Advisory', /^CVE-/.test(rec.id) ? cveUrl : null);
    // "First report" only adds something when it came before the exploit code and exploitation reports.
    const later = [first?.poc?.at, first?.exploited?.at].filter(Boolean);
    if (first?.report && first.report.at > (rec.published_at || '') && later.every(t => first.report.at < t)) add(first.report.at, 'report', 'First report', first.report.source, first.report.url);
    const xs = (rec.exploits || []).filter(x => x.date).sort((a, b) => String(a.date).localeCompare(String(b.date)))[0];
    const poc = [first?.poc, xs && { at: xs.date, source: xs.source, url: xs.url }].filter(Boolean).sort((a, b) => String(a.at).localeCompare(String(b.at)))[0];
    if (poc) add(poc.at, 'poc', 'Exploit code public', poc.source, poc.url);
    if (first?.exploited) add(first.exploited.at, 'exploited', 'First reported exploited', first.exploited.source, first.exploited.url);
    const waf = (sig?.mitigations || []).slice().sort((a, b) => String(a.published).localeCompare(String(b.published)))[0];
    if (waf) add(waf.published, 'waf', 'WAF rule available', waf.source, waf.url);
    if (rec.kev?.date_added) add(rec.kev.date_added, 'kev', 'Added to CISA KEV', 'CISA KEV', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog');
    // Date-only events (CISA lists by day) sort at midday UTC among the timed ones.
    const t = v => Date.parse(String(v).length <= 10 ? `${v}T12:00:00Z` : v);
    ev.sort((a, b) => t(a.at) - t(b.at));
    return { events: ev, awaitingKev: !!first?.exploited && !rec.kev?.listed };
  }

  root.ThreatlineStack = { ECO, PURL_ECO, ECO_KEY, upgradeCommand, timeline, recordHit, recordProducts, vcmp, inRanges, fixFor, cveRangeHit, parseLock, parseManual, parseImages, LOCKFILE_RE, IMAGE_RE, matchPackages, runtimeCandidates, runtimeHit };
})(typeof globalThis !== 'undefined' ? globalThis : window);
