# go-secrets Python preload shim for Windows
import os
import json
import sys

PIPE_NAME = r'\\.\pipe\go-secrets-daemon'

AUTH_TOKEN = os.environ.get('__SECRETS_AUTH_TOKEN')
if not AUTH_TOKEN:
    print('[go-secrets] ERROR: __SECRETS_AUTH_TOKEN not set. Run via: secrets env run -- python ...', file=sys.stderr)
    sys.exit(1)

del os.environ['__SECRETS_AUTH_TOKEN']

secrets_cache = {}

def fetch_all_secrets():
    try:
        import win32file
        
        handle = win32file.CreateFile(
            PIPE_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )
        
        request = json.dumps({
            'type': 'get_all_secrets',
            'auth_token': AUTH_TOKEN
        }).encode('utf-8') + b'\n'
        
        win32file.WriteFile(handle, request)
        
        result, data = win32file.ReadFile(handle, 65536)
        response = json.loads(data.decode('utf-8'))
        
        win32file.CloseHandle(handle)
        
        if response.get('success') and response.get('secrets'):
            return response['secrets']
        else:
            print(f"[go-secrets] ERROR: {response.get('error', 'Failed to fetch secrets')}", file=sys.stderr)
            return {}
        
    except ImportError:
        print('[go-secrets] ERROR: pywin32 not installed. Install with: pip install pywin32', file=sys.stderr)
        return {}
    except Exception as e:
        print(f'[go-secrets] ERROR: Failed to load secrets: {e}', file=sys.stderr)
        return {}

print('[go-secrets] Loading secrets from daemon...')
secrets_cache = fetch_all_secrets()
print(f'[go-secrets] Loaded {len(secrets_cache)} secret(s)')

_original_environ = dict(os.environ)

class SecretsEnviron(dict):
    def __init__(self):
        super().__init__(_original_environ)
        self.update(secrets_cache)
    
    def __getitem__(self, key):
        if key in _original_environ:
            return _original_environ[key]
        if key in secrets_cache:
            return secrets_cache[key]
        raise KeyError(key)
    
    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default
    
    def __contains__(self, key):
        return key in _original_environ or key in secrets_cache
    
    def keys(self):
        return set(_original_environ.keys()) | set(secrets_cache.keys())
    
    def values(self):
        return [self[k] for k in self.keys()]
    
    def items(self):
        return [(k, self[k]) for k in self.keys()]

os.environ = SecretsEnviron()
