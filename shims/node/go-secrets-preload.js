// go-secrets Node.js preload shim for Windows
const net = require('net');

const PIPE_NAME = '\\\\.\\pipe\\go-secrets-daemon';

const AUTH_TOKEN = process.env.__SECRETS_AUTH_TOKEN;
if (!AUTH_TOKEN) {
  console.error('[go-secrets] ERROR: __SECRETS_AUTH_TOKEN not set. Run via: secrets env run -- node ...');
  process.exit(1);
}

delete process.env.__SECRETS_AUTH_TOKEN;

const secretsCache = {};

const helperScript = `
const net = require('net');
const AUTH_TOKEN = process.argv[2];
const PIPE_NAME = '\\\\\\\\.\\\\pipe\\\\go-secrets-daemon';

const client = net.connect(PIPE_NAME, () => {
  const request = JSON.stringify({
    type: 'get_all_secrets',
    auth_token: AUTH_TOKEN
  });
  client.end(request + '\\n');
});

let responseData = '';
client.on('data', (data) => {
  responseData += data.toString();
});

client.on('end', () => {
  try {
    const response = JSON.parse(responseData);
    if (response.success && response.secrets) {
      console.log(JSON.stringify(response.secrets));
    } else {
      console.error('ERROR: ' + (response.error || 'Failed'));
      process.exit(1);
    }
  } catch (err) {
    console.error('ERROR: ' + err.message);
    process.exit(1);
  }
});

client.on('error', (err) => {
  console.error('ERROR: ' + err.message);
  process.exit(1);
});
`;

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const helperPath = path.join(os.tmpdir(), 'go-secrets-helper.js');
fs.writeFileSync(helperPath, helperScript);

try {
  console.log('[go-secrets] Loading secrets from daemon...');
  const result = execFileSync('node', [helperPath, AUTH_TOKEN], {
    encoding: 'utf8',
    timeout: 5000
  });
  const secrets = JSON.parse(result.trim());
  Object.assign(secretsCache, secrets);
  console.log(`[go-secrets] Loaded ${Object.keys(secrets).length} secret(s)`);
} catch (err) {
  console.error(`[go-secrets] WARNING: Failed to load secrets: ${err.message}`);
}

try { fs.unlinkSync(helperPath); } catch (e) {}

const originalEnv = process.env;

const envProxy = new Proxy(originalEnv, {
  get(target, prop) {
    if (prop in target) {
      return target[prop];
    }
    if (prop in secretsCache) {
      return secretsCache[prop];
    }
    return undefined;
  },

  has(target, prop) {
    return prop in target || prop in secretsCache;
  },

  ownKeys(target) {
    return [...Reflect.ownKeys(target), ...Object.keys(secretsCache)];
  },

  getOwnPropertyDescriptor(target, prop) {
    if (prop in target) {
      return Object.getOwnPropertyDescriptor(target, prop);
    }
    
    if (prop in secretsCache) {
      return {
        enumerable: true,
        configurable: true,
        writable: false,
        value: secretsCache[prop]
      };
    }

    return undefined;
  }
});

Object.defineProperty(process, 'env', {
  get: () => envProxy,
  set: () => {
    throw new Error('Cannot replace process.env');
  },
  enumerable: true,
  configurable: false
});
