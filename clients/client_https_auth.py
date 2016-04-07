import requests;
from requests.auth import HTTPDigestAuth
import sys;
import time;
username = 'andrey';
password = 'password';

start=time.time();
for i in range(1, 10000):
    r = requests.get('https://127.0.0.1/', headers={'Connection':'close'}, verify=False, auth=HTTPDigestAuth(username, password));
    print(i, ",", time.time()-start);
#print(r.headers);
#print(r.text);
