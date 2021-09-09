import os.path
from pprint import pprint
from virustotal_python import Virustotal

vtotal = Virustotal(API_KEY="5b34fd9e6afc7c01df9f9f9092a5b2d690ae3ae0d676e04ad4ab5df910567e49")
# Declare PATH to file
FILE_PATH = "icon.ico"

# Create dictionary containing the file to send for multipart encoding upload
files = {"file": (os.path.basename(FILE_PATH), open(os.path.abspath(FILE_PATH), "rb"))}

# v2 example
resp = vtotal.request("file/scan", files=files, method="POST")

# The v2 API returns a response_code
# This property retrieves it from the JSON response
print(resp.response_code)
# Print JSON response from the API
pprint(resp.json())
