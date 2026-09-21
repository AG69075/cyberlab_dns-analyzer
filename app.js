const express = require('express');
const { execFileSync, execFile, spawn, exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const net = require('net');
const dns = require('dns').promises;
const rateLimit = require('express-rate-limit');

const execFileP = promisify(execFile);

const app = express();
app.set('trust proxy', 1);

// In-memory job store
// { jobId: { status: 'pending'|'done'|'error', data?, error?, startedAt } }
const jobs = {};
const MAX_CONCURRENT_JOBS = 3;

// Auto-cleanup jobs older than 1 hour
setInterval(() => {
  const now = Date.now();
  for (const jobId in jobs) {
    if (now - jobs[jobId].startedAt > 3600000) {
      delete jobs[jobId];
    }
  }
}, 600000);

// --- Input validation ---
// This backend shells out to `dig` and `sublist3r`. Every value below is
// validated against a strict allow-list before it ever reaches a child
// process argument vector, to rule out command/argument injection.

const HOSTNAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const ALLOWED_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'PTR', 'AXFR', 'ANY'];

function isValidHost(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 253) return false;
  if (net.isIP(value) !== 0) return true;
  return HOSTNAME_RE.test(value);
}

function isValidPort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function sanitizeForLog(value) {
  return String(value).replace(/[\r\n]/g, ' ');
}

// CORS - restricted to the known Cloudflare Worker proxy in front of this
// service. Configurable so the allow-list doesn't need a code change per
// environment.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://cyberlab-dns-proxy.axelginepro.workers.dev')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Vary', 'Origin');
  }
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.use(express.json());

// Shared-secret check between the Cloudflare Worker proxy and this origin.
// CORS only stops browsers; the Worker calls this backend server-to-server,
// so if port 4002 is ever reachable directly (bypassing the Worker), this
// token is what actually blocks it. Fails closed: refuses to start without
// a token configured, rather than silently running with an open /api.
const INTERNAL_API_TOKEN = process.env.INTERNAL_API_TOKEN;
if (!INTERNAL_API_TOKEN) {
  console.error('FATAL: INTERNAL_API_TOKEN is not set. Refusing to start with an open /api surface.');
  process.exit(1);
}

app.use('/api', (req, res, next) => {
  const token = req.headers['x-internal-token'];
  if (token !== INTERNAL_API_TOKEN) {
    return res.status(401).json({ success: false, error: 'unauthorized' });
  }
  next();
});

// Rate limiting - the /api routes shell out to dig / spawn sublist3r
// processes, so unrestricted request volume is a direct resource-exhaustion
// vector.
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api', apiLimiter);

// DNS Lookup
app.post('/api/dns', (req, res) => {
  const { domain, server, port, type } = req.body;

  if (!domain || !server) {
    return res.status(400).json({ success: false, error: 'domain and server are required' });
  }
  if (!isValidHost(domain)) {
    return res.status(400).json({ success: false, error: 'invalid domain' });
  }
  if (!isValidHost(server)) {
    return res.status(400).json({ success: false, error: 'invalid server' });
  }
  if (!isValidPort(port)) {
    return res.status(400).json({ success: false, error: 'invalid port' });
  }
  if (!ALLOWED_RECORD_TYPES.includes(type)) {
    return res.status(400).json({ success: false, error: 'invalid type' });
  }

  console.log(`DNS request: domain=${sanitizeForLog(domain)}, server=${sanitizeForLog(server)}, port=${port}, type=${type}`);

  try {
    const args = [`@${server}`, '-p', String(port), domain];
    if (type === 'AXFR') {
      args.push('AXFR');
    } else {
      args.push(type, '+short');
    }

    console.log(`Running: dig ${args.join(' ')}`);

    // execFileSync (no shell) - args are passed straight to execve, so shell
    // metacharacters in domain/server/type cannot be interpreted.
    const output = execFileSync('dig', args, {
      encoding: 'utf-8',
      timeout: 10000,
      maxBuffer: 10 * 1024 * 1024
    });

    let results;
    if (type === 'AXFR') {
      results = output
        .split('\n')
        .filter(line => !line.startsWith(';') && line.trim().length > 0);
    } else {
      results = output.trim().split('\n').filter(line => line.length > 0);
    }

    res.json({ success: true, data: results });
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// DNS security posture - read-only assessment built entirely from `dig`
// queries: SPF / DMARC / DKIM (email spoofing resistance), DNSSEC, CAA, MX and
// NS provider diversity. All lookups run in parallel so the whole audit is a
// few seconds even when some records are missing / slow.
app.post('/api/dns/posture', async (req, res) => {
  const { domain } = req.body;

  if (!domain) {
    return res.status(400).json({ success: false, error: 'domain is required' });
  }
  if (!isValidHost(domain)) {
    return res.status(400).json({ success: false, error: 'invalid domain' });
  }

  console.log(`Posture request: domain=${sanitizeForLog(domain)}`);

  try {
    const checks = await Promise.all([
      analyseSpf(domain),
      analyseDmarc(domain),
      analyseDkim(domain),
      analyseDnssec(domain),
      analyseCaa(domain),
      analyseMx(domain),
      analyseNs(domain),
    ]);
    const score = {
      crit: checks.filter(c => c.severity === 'crit').length,
      warn: checks.filter(c => c.severity === 'warn').length,
      ok: checks.filter(c => c.severity === 'ok').length,
      info: checks.filter(c => c.severity === 'info').length,
    };
    res.json({ success: true, domain, checks, score });
  } catch (error) {
    console.error('Posture error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Subdomains - Start job (returns immediately)
app.post('/api/subdomains/start', (req, res) => {
  const { domain, bruteforce, probe } = req.body;

  if (!domain) {
    return res.status(400).json({ success: false, error: 'domain is required' });
  }
  if (!isValidHost(domain)) {
    return res.status(400).json({ success: false, error: 'invalid domain' });
  }

  // Booleans arrive either as real JSON booleans or as "true"/"false" strings
  // depending on the caller; normalise both.
  const opts = {
    bruteforce: bruteforce === true || bruteforce === 'true',
    probe: probe === true || probe === 'true',
  };

  const activeJobs = Object.values(jobs).filter(j => j.status === 'pending').length;
  if (activeJobs >= MAX_CONCURRENT_JOBS) {
    return res.status(429).json({ success: false, error: 'too many scans running, try again shortly' });
  }

  const jobId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  jobs[jobId] = { status: 'pending', startedAt: Date.now() };

  // Immediate response - Cloudflare will not timeout
  res.json({ success: true, job_id: jobId });

  // Run enumeration (Sublist3r + optional brute force + optional HTTP probe)
  // in background
  _runEnumeration(domain, opts, jobId);
});

// Subdomains - Poll job status
app.get('/api/subdomains/status/:jobId', (req, res) => {
  const job = jobs[req.params.jobId];
  if (!job) {
    return res.status(404).json({ success: false, error: 'Job not found or expired' });
  }
  res.json({ success: true, ...job });
});

// Deprecated route kept for compatibility
app.post('/api/subdomains', (req, res) => {
  return res.status(410).json({
    success: false,
    error: 'Deprecated. Use POST /api/subdomains/start then GET /api/subdomains/status/:jobId'
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', activeJobs: Object.keys(jobs).length });
});

// --- DNS security posture helpers ---------------------------------------
// Each `analyse*` returns { key, label, severity, summary, facts[] }.
// severity: 'ok' | 'warn' | 'crit' | 'info'.

const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 's1', 'k1', 'mail', 'dkim'];

// `domain` is already validated by isValidHost() before any analyse* runs, and
// the derived names below only prepend fixed ASCII labels, so nothing
// injectable reaches dig's argv (execFile, no shell).
async function digShort(name, type) {
  try {
    const { stdout } = await execFileP(
      'dig',
      ['+short', '+time=2', '+tries=1', type, name],
      { timeout: 6000, maxBuffer: 2 * 1024 * 1024 },
    );
    return stdout
      .trim()
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

// dig prints long TXT records as several "chunk" quoted strings on one line.
function unquoteTxt(line) {
  return line.replace(/^"|"$/g, '').replace(/"\s+"/g, '');
}

function registrableDomain(host) {
  return host.replace(/\.$/, '').toLowerCase().split('.').slice(-2).join('.');
}

async function analyseSpf(domain) {
  const txt = (await digShort(domain, 'TXT')).map(unquoteTxt);
  const spf = txt.find(r => r.toLowerCase().startsWith('v=spf1'));
  if (!spf) {
    return {
      key: 'spf', label: 'SPF', severity: 'crit',
      summary: 'Absent — aucun émetteur autorisé déclaré',
      facts: ["N'importe quel serveur peut envoyer du mail au nom de ce domaine."],
    };
  }
  const qualifier = (spf.match(/([-~?+])all\b/) || [])[1];
  const lookups = (spf.match(/(^|\s)(a|mx|ptr|exists:|include:|redirect=)/gi) || []).length;
  const facts = [spf];
  let severity = 'ok';
  let summary;
  switch (qualifier) {
    case '-': summary = 'Présent, politique stricte (-all)'; break;
    case '~': summary = 'Présent, mais soft fail (~all)'; severity = 'warn';
      facts.push('~all : les mails usurpés sont généralement acceptés puis marqués.'); break;
    case '?': summary = 'Présent, mais neutre (?all)'; severity = 'warn';
      facts.push('?all : aucune protection effective.'); break;
    case '+': summary = 'Présent, mais +all (dangereux)'; severity = 'crit';
      facts.push('+all autorise explicitement tout le monde.'); break;
    default: summary = 'Présent, sans mécanisme "all"'; severity = 'warn';
      facts.push('Pas de "all" final : comportement non défini selon les récepteurs.');
  }
  facts.push(`${lookups} terme(s) à résolution DNS dans l'enregistrement (limite RFC : 10 ; includes imbriqués non comptés ici).`);
  if (lookups > 10) {
    severity = 'crit';
    facts.push('Dépassement probable de la limite de 10 lookups → SPF ignoré ("permerror").');
  }
  return { key: 'spf', label: 'SPF', severity, summary, facts };
}

async function analyseDmarc(domain) {
  const txt = (await digShort(`_dmarc.${domain}`, 'TXT')).map(unquoteTxt);
  const dmarc = txt.find(r => r.toLowerCase().startsWith('v=dmarc1'));
  if (!dmarc) {
    return {
      key: 'dmarc', label: 'DMARC', severity: 'crit',
      summary: 'Absent — aucune politique anti-usurpation',
      facts: ["Sans DMARC, SPF et DKIM ne protègent pas l'adresse « From: » affichée."],
    };
  }
  const p = (dmarc.match(/\bp=([a-z]+)/i) || [])[1] || 'none';
  const sp = (dmarc.match(/\bsp=([a-z]+)/i) || [])[1];
  const pct = (dmarc.match(/\bpct=(\d+)/i) || [])[1];
  const hasRua = /\brua=/i.test(dmarc);
  const facts = [dmarc];
  let severity = 'ok';
  if (p === 'none') {
    severity = 'warn';
    facts.push('p=none : surveillance seule, aucun blocage des mails usurpés.');
  } else if (p === 'quarantine') {
    facts.push('p=quarantine : les mails usurpés partent en spam.');
  } else if (p === 'reject') {
    facts.push('p=reject : les mails usurpés sont rejetés.');
  }
  if (pct && Number(pct) < 100) {
    if (severity === 'ok') severity = 'warn';
    facts.push(`pct=${pct} : politique appliquée à ${pct}% des mails seulement.`);
  }
  if (!hasRua) {
    if (severity === 'ok') severity = 'warn';
    facts.push('Pas de rua= : aucun rapport agrégé, angle mort sur les abus.');
  }
  if (sp) facts.push(`sp=${sp} : politique dédiée aux sous-domaines.`);
  return { key: 'dmarc', label: 'DMARC', severity, summary: `Présent, p=${p}`, facts };
}

async function analyseDkim(domain) {
  const hits = await Promise.all(DKIM_SELECTORS.map(async sel => {
    const name = `${sel}._domainkey.${domain}`;
    const txt = (await digShort(name, 'TXT')).map(unquoteTxt);
    // Real DKIM records carry either v=DKIM1 or a long base64 public key.
    if (txt.some(r => /v=DKIM1/i.test(r) || /(^|;|\s)p=[A-Za-z0-9+/]{40,}/.test(r))) return sel;
    if ((await digShort(name, 'CNAME')).length) return `${sel} (CNAME)`;
    return null;
  }));
  const found = hits.filter(Boolean);
  if (found.length === 0) {
    return {
      key: 'dkim', label: 'DKIM', severity: 'info',
      summary: 'Aucun sélecteur courant trouvé',
      facts: [
        'DKIM utilise des sélecteurs arbitraires : une absence ici ne prouve pas une absence totale.',
        `Sélecteurs testés : ${DKIM_SELECTORS.join(', ')}.`,
      ],
    };
  }
  return {
    key: 'dkim', label: 'DKIM', severity: 'ok',
    summary: `Sélecteur(s) actif(s) : ${found.join(', ')}`, facts: [],
  };
}

async function analyseDnssec(domain) {
  const [ds, dnskey] = await Promise.all([
    digShort(domain, 'DS'),
    digShort(domain, 'DNSKEY'),
  ]);
  if (ds.length && dnskey.length) {
    return {
      key: 'dnssec', label: 'DNSSEC', severity: 'ok',
      summary: 'Activé (DS chez le parent + DNSKEY publiée)',
      facts: [`${ds.length} enregistrement(s) DS.`],
    };
  }
  if (ds.length && !dnskey.length) {
    return {
      key: 'dnssec', label: 'DNSSEC', severity: 'crit',
      summary: 'Chaîne cassée : DS présent, DNSKEY absente',
      facts: ['Les résolveurs validants renverront SERVFAIL — le domaine peut devenir injoignable.'],
    };
  }
  return {
    key: 'dnssec', label: 'DNSSEC', severity: 'warn',
    summary: 'Non activé — zone non signée',
    facts: ['Pas de protection contre les réponses DNS falsifiées / l\'empoisonnement de cache.'],
  };
}

async function analyseCaa(domain) {
  const caa = await digShort(domain, 'CAA');
  if (caa.length === 0) {
    return {
      key: 'caa', label: 'CAA', severity: 'warn',
      summary: 'Absent — toute autorité de certification peut émettre',
      facts: ['Un enregistrement CAA restreint les CA autorisées à délivrer un certificat pour ce domaine.'],
    };
  }
  return {
    key: 'caa', label: 'CAA', severity: 'ok',
    summary: `${caa.length} règle(s) définie(s)`, facts: caa,
  };
}

async function analyseMx(domain) {
  const mx = await digShort(domain, 'MX');
  if (mx.length === 0) {
    return {
      key: 'mx', label: 'MX', severity: 'info',
      summary: 'Aucun MX — le domaine ne reçoit pas de mail',
      facts: ['Gardez tout de même SPF -all + DMARC p=reject pour bloquer l\'usurpation.'],
    };
  }
  return {
    key: 'mx', label: 'MX', severity: 'ok',
    summary: `${mx.length} serveur(s) de messagerie`,
    facts: mx.map(m => `  ${m.replace(/\.$/, '')}`),
  };
}

async function analyseNs(domain) {
  const ns = (await digShort(domain, 'NS')).map(h => h.replace(/\.$/, '').toLowerCase());
  if (ns.length === 0) {
    return { key: 'ns', label: 'Serveurs de noms', severity: 'crit', summary: 'Aucun NS retourné', facts: [] };
  }
  const providers = [...new Set(ns.map(registrableDomain))];
  const facts = ns.map(h => `  ${h}`);
  if (ns.length < 2) {
    return {
      key: 'ns', label: 'Serveurs de noms', severity: 'warn',
      summary: 'Un seul NS — point de défaillance unique', facts,
    };
  }
  if (providers.length === 1) {
    return {
      key: 'ns', label: 'Serveurs de noms', severity: 'info',
      summary: `${ns.length} NS, tous chez ${providers[0]} — pas de redondance de fournisseur`, facts,
    };
  }
  return {
    key: 'ns', label: 'Serveurs de noms', severity: 'ok',
    summary: `${ns.length} NS répartis sur ${providers.length} fournisseurs`, facts,
  };
}

// --- HTTP probe ------------------------------------------------------------
// Runs AFTER subdomain discovery, on the merged host list. Node 22 ships a
// global fetch, so this needs no extra dependency. Each host is resolved,
// then probed https-first then http, following at most one redirect
// manually so the Location can be reported.
//
// SSRF guard: a host that resolves to a private / loopback / link-local
// address (including the cloud metadata IP 169.254.169.254) is reported as
// alive but is NEVER fetched. This backend must not be usable as a pivot to
// reach internal services from its network position.

const PROBE_CONCURRENCY = 20;
const PROBE_TIMEOUT_MS = 6000;
const MAX_PROBE_HOSTS = 400;
const TITLE_RE = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i;

function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;            // link-local + metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;  // CGNAT 100.64/10
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;      // ULA
  if (/^fe[89ab]/.test(lower)) return true;                              // link-local
  if (lower.startsWith('::ffff:')) return isPrivateAddress(lower.slice(7)); // v4-mapped
  return false;
}

async function resolveHost(host) {
  try {
    const addrs = await dns.lookup(host, { all: true });
    return [...new Set(addrs.map(a => a.address))];
  } catch {
    return [];
  }
}

async function readCappedBody(resp, cap) {
  const reader = resp.body && resp.body.getReader ? resp.body.getReader() : null;
  if (!reader) return '';
  const decoder = new TextDecoder();
  let received = 0;
  let out = '';
  try {
    while (received < cap) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.length;
      out += decoder.decode(value, { stream: true });
      if (out.includes('</title>')) break;
    }
  } catch {
    // partial body is fine
  } finally {
    try { await reader.cancel(); } catch { /* ignore */ }
  }
  return out;
}

async function fetchScheme(scheme, host) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
  try {
    const resp = await fetch(`${scheme}://${host}/`, {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
      headers: { 'User-Agent': 'Cyberlab-DNS-Analyzer/1.0 (+recon)' },
    });
    let title = null;
    const ct = resp.headers.get('content-type') || '';
    if (ct.includes('text/html') || ct === '') {
      const body = await readCappedBody(resp, 48 * 1024);
      const m = TITLE_RE.exec(body);
      if (m) title = m[1].trim().replace(/\s+/g, ' ').slice(0, 200) || null;
    }
    return {
      scheme,
      status: resp.status,
      server: resp.headers.get('server') || null,
      redirect: resp.headers.get('location') || null,
      title,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function probeOne(host) {
  const addresses = await resolveHost(host);
  if (addresses.length === 0) {
    return { host, addresses, private: false, http: null };
  }
  if (addresses.some(isPrivateAddress)) {
    return { host, addresses, private: true, http: null };
  }
  for (const scheme of ['https', 'http']) {
    const res = await fetchScheme(scheme, host);
    if (res) return { host, addresses, private: false, http: res };
  }
  return { host, addresses, private: false, http: null };
}

async function probeAll(hosts) {
  const targets = hosts.slice(0, MAX_PROBE_HOSTS);
  const results = new Array(targets.length);
  let cursor = 0;
  async function worker() {
    while (cursor < targets.length) {
      const idx = cursor++;
      results[idx] = await probeOne(targets[idx]);
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(PROBE_CONCURRENCY, targets.length) }, worker)
  );
  return results;
}

// --- Enumeration runner ---------------------------------------------------
// Sublist3r (passive OSINT) + optional `-b` brute force (subbrute, ~2000
// common names) + optional Node-side HTTP probe on the merged list.
function _runEnumeration(domain, opts, jobId) {
  exec('which python3', (error) => {
    if (error) {
      jobs[jobId] = { status: 'error', error: 'python3 not found', startedAt: jobs[jobId].startedAt };
      return;
    }

    exec('python3 -c "import sublist3r"', (error) => {
      if (error) {
        jobs[jobId] = { status: 'error', error: 'sublist3r not installed (pip3 install sublist3r)', startedAt: jobs[jobId].startedAt };
        return;
      }

      const outputFile = `/tmp/sublist3r_${jobId}.txt`;
      const args = ['-m', 'sublist3r', '-d', domain, '-o', outputFile];

      if (opts.bruteforce) {
        // -b enables subbrute (bundled ~2000-name wordlist, with wildcard
        // detection built in); -t caps its forked resolver workers.
        args.push('-b', '-t', '40');
      }

      console.log(`[Job ${jobId}] Running: python3 ${args.join(' ')} (probe=${opts.probe})`);

      // detached: true makes this process the leader of its own process
      // group, so the timeout handler below can kill the whole group
      // (subbrute forks itself into dozens of worker processes for
      // concurrent DNS resolution - killing only the top-level PID leaves
      // those forks running as orphans indefinitely).
      const python = spawn('python3', args, { detached: true });
      let errorString = '';

      python.stderr.on('data', (data) => {
        errorString += data.toString();
      });

      python.on('close', async (code) => {
        console.log(`[Job ${jobId}] Exited with code ${code}`);

        if (code !== 0) {
          jobs[jobId] = {
            status: 'error',
            error: errorString || 'Sublist3r failed',
            startedAt: jobs[jobId].startedAt
          };
          return;
        }

        try {
          let uniqueSubdomains = [];

          // Sublist3r n'écrit le fichier -o que s'il trouve au moins un
          // sous-domaine. Exit code 0 + fichier absent = 0 résultats, pas
          // une erreur.
          if (fs.existsSync(outputFile)) {
            const fileContent = fs.readFileSync(outputFile, 'utf-8');
            fs.unlinkSync(outputFile);

            const subdomains = fileContent
              .split('\n')
              .map(line => line.trim())
              .filter(line => {
                if (!line || line.length === 0) return false;
                if (line.includes('Usage:')) return false;
                if (line.includes('[')) return false;
                if (line.includes('|')) return false;
                if (line.includes('Enumerating')) return false;
                if (line.includes('Total')) return false;
                if (line.includes('python')) return false;
                if (!line.includes('.')) return false;
                return HOSTNAME_RE.test(line);
              });

            uniqueSubdomains = [...new Set(subdomains)].sort();
          }

          let results = null;
          const stats = { total: uniqueSubdomains.length };

          if (opts.probe && uniqueSubdomains.length > 0) {
            console.log(`[Job ${jobId}] Probing ${Math.min(uniqueSubdomains.length, MAX_PROBE_HOSTS)} host(s) over HTTP`);
            results = await probeAll(uniqueSubdomains);
            stats.probed = results.length;
            stats.alive = results.filter(r => r.addresses.length > 0).length;
            stats.httpOk = results.filter(r => r.http && r.http.status < 400).length;
          }

          jobs[jobId] = {
            status: 'done',
            data: {
              domain,
              subdomains: uniqueSubdomains,   // kept for backward compatibility
              count: uniqueSubdomains.length,
              bruteforce: !!opts.bruteforce,
              probe: !!opts.probe,
              results,                        // null when probe disabled
              stats,
            },
            startedAt: jobs[jobId].startedAt
          };

          console.log(`[Job ${jobId}] Found ${uniqueSubdomains.length} subdomains`);
        } catch (err) {
          jobs[jobId] = { status: 'error', error: `Failed to process results: ${err.message}`, startedAt: jobs[jobId].startedAt };
        }
      });

      python.on('error', (error) => {
        jobs[jobId] = { status: 'error', error: `Spawn error: ${error.message}`, startedAt: jobs[jobId].startedAt };
      });

      // 20 min timeout
      setTimeout(() => {
        if (jobs[jobId] && jobs[jobId].status === 'pending') {
          // Negative PID targets the whole process group (see `detached:
          // true` above), so subbrute's forked workers get reaped too -
          // python.kill() alone only hits the top-level process.
          try {
            process.kill(-python.pid, 'SIGKILL');
          } catch (err) {
            python.kill('SIGKILL');
          }
          console.log(`[Job ${jobId}] Timed out after 20 minutes, process group killed`);
          jobs[jobId] = { status: 'error', error: 'Timeout: scan exceeded 20 minutes', startedAt: jobs[jobId].startedAt };
        }
      }, 1200000);
    });
  });
}

app.listen(4002, '0.0.0.0', () => {
  console.log('DNS Backend listening on port 4002');
});