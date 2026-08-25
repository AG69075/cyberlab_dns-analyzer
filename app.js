const express = require('express');
const { execFileSync, spawn, exec } = require('child_process');
const fs = require('fs');
const net = require('net');
const rateLimit = require('express-rate-limit');

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
const PORTS_LIST_RE = /^\d{1,5}(,\d{1,5})*$/;
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

// Subdomains - Start job (returns immediately)
app.post('/api/subdomains/start', (req, res) => {
  const { domain, bruteforce, ports } = req.body;

  if (!domain) {
    return res.status(400).json({ success: false, error: 'domain is required' });
  }
  if (!isValidHost(domain)) {
    return res.status(400).json({ success: false, error: 'invalid domain' });
  }
  if (ports && !PORTS_LIST_RE.test(ports)) {
    return res.status(400).json({ success: false, error: 'invalid ports (expected comma-separated port numbers)' });
  }

  const activeJobs = Object.values(jobs).filter(j => j.status === 'pending').length;
  if (activeJobs >= MAX_CONCURRENT_JOBS) {
    return res.status(429).json({ success: false, error: 'too many scans running, try again shortly' });
  }

  const jobId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  jobs[jobId] = { status: 'pending', startedAt: Date.now() };

  // Immediate response - Cloudflare will not timeout
  res.json({ success: true, job_id: jobId });

  // Run Sublist3r in background
  _runSublistr(domain, Boolean(bruteforce), ports, jobId);
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

// Sublist3r background runner
function _runSublistr(domain, bruteforce, ports, jobId) {
  exec('which python3', (error, stdout) => {
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

      if (bruteforce) args.push('-b');
      if (ports && ports.length > 0) {
        args.push('-p');
        args.push(ports);
      }

      console.log(`[Job ${jobId}] Running: python3 ${args.join(' ')}`);

      const python = spawn('python3', args);
      let errorString = '';

      python.stderr.on('data', (data) => {
        errorString += data.toString();
      });

      python.on('close', (code) => {
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
          // Sublist3r n'écrit le fichier -o que s'il trouve au moins un
          // sous-domaine. Exit code 0 + fichier absent = 0 résultats, pas
          // une erreur.
          if (!fs.existsSync(outputFile)) {
            jobs[jobId] = {
              status: 'done',
              data: { domain, subdomains: [], count: 0 },
              startedAt: jobs[jobId].startedAt
            };
            console.log(`[Job ${jobId}] Found 0 subdomains (no output file)`);
            return;
          }

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

          const uniqueSubdomains = [...new Set(subdomains)].sort();

          jobs[jobId] = {
            status: 'done',
            data: {
              domain,
              subdomains: uniqueSubdomains,
              count: uniqueSubdomains.length
            },
            startedAt: jobs[jobId].startedAt
          };

          console.log(`[Job ${jobId}] Found ${uniqueSubdomains.length} subdomains`);
        } catch (err) {
          jobs[jobId] = { status: 'error', error: `Failed to read results: ${err.message}`, startedAt: jobs[jobId].startedAt };
        }
      });

      python.on('error', (error) => {
        jobs[jobId] = { status: 'error', error: `Spawn error: ${error.message}`, startedAt: jobs[jobId].startedAt };
      });

      // 20 min timeout
      setTimeout(() => {
        if (jobs[jobId] && jobs[jobId].status === 'pending') {
          python.kill();
          jobs[jobId] = { status: 'error', error: 'Timeout: scan exceeded 20 minutes', startedAt: jobs[jobId].startedAt };
        }
      }, 1200000);
    });
  });
}

app.listen(4002, '0.0.0.0', () => {
  console.log('DNS Backend listening on port 4002');
});