import sys, os
sys.stdout.reconfigure(encoding='utf-8')

env = {}
for line in open('.env', encoding='utf-8'):
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, _, v = line.partition('=')
        env[k.strip()] = v.strip()
os.environ.update(env)
print('Credentials loaded from .env')

# 1. Test MongoDB
print()
print('[1/2] Testing MongoDB Atlas connection...')
try:
    import pymongo
    uri = env['MONGODB_URI']
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=8000)
    client.admin.command('ping')
    print('  OK  MongoDB Atlas is reachable!')
    db = client['deployguard']
    colls = db.list_collection_names()
    print(f'  Existing collections: {colls if colls else "(empty - will be seeded)"}')
    client.close()
except Exception as e:
    print(f'  FAIL: {e}')

# 2. Test OpenAI
print()
print('[2/2] Testing OpenAI API key...')
try:
    import urllib.request, json
    oai_key = env['OPENAI_API_KEY']
    req = urllib.request.Request(
        'https://api.openai.com/v1/models',
        headers={'Authorization': 'Bearer ' + oai_key}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read())
        models = [m['id'] for m in data.get('data', []) if 'gpt-4o' in m['id']]
        print('  OK  OpenAI key valid!')
        print(f'  Available GPT-4o models: {models[:3]}')
except Exception as e:
    print(f'  FAIL: {e}')

print()
print('Done.')
