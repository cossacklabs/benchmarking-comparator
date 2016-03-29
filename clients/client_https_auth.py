import requests;
from requests.auth import HTTPDigestAuth

username = 'andrey';
password = 'password';

r = requests.get('https://127.0.0.1/', verify=False, auth=HTTPDigestAuth(username, password));

print(r.headers);
print(r.text);
