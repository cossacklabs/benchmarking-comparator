import requests;
from requests.auth import HTTPDigestAuth
import time;

username = 'andrey';
password = 'password';

start=time.time();
for i in range(1, 10000):
    r = requests.get('http://127.0.0.1:8080/http-auth/', auth=HTTPDigestAuth(username, password));
    print(i, ",", time.time()-start);
#print(r.headers);
#print(r.text);
