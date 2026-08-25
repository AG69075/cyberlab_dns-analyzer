const express = require('express');
const { execSync, spawn } = require('child_process');
const { exec } = require('child_process');

const app = express();

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Max-Age', '86400');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json());

app.post('/api/dns', (req, res) => {
  const { domain, server, port, type } = req.body;

  console.log(`Requête DNS: domain=${domain}, server=${server}, port=${port}, type=${type}`);

  if (!domain || !server) {
    return res.status(400).json({
      success: false,
      error: 'domain et server requis'
    });
  }

  try {
    let cmd;
    if (type === 'AXFR') {
      cmd = `dig @${server} -p ${port} ${domain} AXFR 2>&1`;
    } else {
      cmd = `dig @${server} -p ${port} ${domain} ${type} +short 2>&1`;
    }
    
    console.log(`Exécution: ${cmd}`);
    
    const output = execSync(cmd, { 
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
    
    res.json({ 
      success: true, 
      data: results 
    });
  } catch (error) {
    console.error('Erreur:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

app.post('/api/subdomains', (req, res) => {
  const { domain, bruteforce, ports, verbose } = req.body;

  console.log(`Sublist3r: domain=${domain}, bruteforce=${bruteforce}, ports=${ports}`);

  if (!domain) {
    return res.status(400).json({
      success: false,
      error: 'domain requis'
    });
  }

  exec('which python3', (error, stdout, stderr) => {
    if (error) {
      console.error('Python3 non trouvé:', error);
      return res.status(500).json({
        success: false,
        error: 'Python3 non installé. Installez-le avec: apt-get install python3'
      });
    }

    const pythonPath = stdout.trim();
    console.log(`Python3 trouvé à: ${pythonPath}`);

    exec('python3 -c "import sublist3r"', (error, stdout, stderr) => {
      if (error) {
        console.error('Sublist3r non trouvé:', error);
        return res.status(500).json({
          success: false,
          error: 'Sublist3r non installé. Installez-le avec: pip3 install sublist3r'
        });
      }

      const args = ['-m', 'sublist3r', '-d', domain, '-o', '/tmp/sublist3r_output.txt'];

      if (bruteforce) {
        args.push('-b');
      }

      if (ports && ports.length > 0) {
        args.push('-p');
        args.push(ports);
      }

      console.log(`Exécution: python3 ${args.join(' ')}`);

      const python = spawn('python3', args);
      let errorString = '';
      let responseSent = false;

      const sendResponse = (isError, data) => {
        if (responseSent) return;
        responseSent = true;

        if (isError) {
          res.status(500).json({
            success: false,
            error: data
          });
        } else {
          res.json({
            success: true,
            data: data
          });
        }
      };

      python.stdout.on('data', (data) => {
        console.log(`stdout: ${data}`);
      });

      python.stderr.on('data', (data) => {
        errorString += data.toString();
        console.error(`stderr: ${data}`);
      });

      python.on('close', (code) => {
        console.log(`Processus Python terminé avec le code ${code}`);

        if (code !== 0) {
          return sendResponse(true, errorString || 'Erreur lors de l\'exécution de Sublist3r');
        }

        try {
          const fs = require('fs');
          const outputFile = '/tmp/sublist3r_output.txt';
          
          if (!fs.existsSync(outputFile)) {
            return sendResponse(true, 'Aucun fichier de résultat généré');
          }

          const fileContent = fs.readFileSync(outputFile, 'utf-8');
          
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
              
              const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
              return domainPattern.test(line);
            });

          const uniqueSubdomains = [...new Set(subdomains)].sort();

          fs.unlinkSync(outputFile);

          sendResponse(false, {
            domain: domain,
            subdomains: uniqueSubdomains,
            count: uniqueSubdomains.length
          });
        } catch (err) {
          console.error('Erreur lecture fichier:', err);
          sendResponse(true, `Erreur lecture résultats: ${err.message}`);
        }
      });

      python.on('error', (error) => {
        console.error('Erreur spawn:', error);
        sendResponse(true, `Erreur d'exécution: ${error.message}`);
      });

      setTimeout(() => {
        if (!responseSent) {
          python.kill();
          sendResponse(true, 'Timeout: le scan a pris trop de temps (20 minutes max)');
        }
      }, 1200000);
    });
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

app.listen(4002, '0.0.0.0', () => {
  console.log('DNS Backend listening on port 4002');
});
