import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi

API_KEY = '5b34fd9e6afc7c01df9f9f9092a5b2d690ae3ae0d676e04ad4ab5df910567e49'
EICAR = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".encode('utf-8')
EICAR_MD5 = hashlib.md5(EICAR).hexdigest()

vt = VirusTotalPublicApi(API_KEY)

response = vt.get_file_report(EICAR_MD5)

json_string = str(json.dumps(response, sort_keys=False, indent=4))
data = json.loads(json_string)
print()

