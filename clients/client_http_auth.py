import requests;
from requests.auth import HTTPDigestAuth

username = 'andrey';
password = 'password';

r = requests.get('http://127.0.0.1:8080/http-auth/', auth=HTTPDigestAuth(username, password));

#print(r.headers);
#print(r.text);
