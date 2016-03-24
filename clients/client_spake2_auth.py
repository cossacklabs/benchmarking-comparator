import requests;
from requests.auth import HTTPDigestAuth
import base64;
from spake2 import SPAKE2_A

username = 'andrey';
password = 'password';

r = requests.get('http://127.0.0.1:8080/spake2-auth/');
if r.status_code ==401 and r.headers["WWW-Authenticate"] == "Spake2":
    server_name = r.headers["WWW-Authenticate-Spake2-Name"];
    s = SPAKE2_A(password.encode('UTF-8'), idA=username.encode('UTF-8'), idB=server_name.encode('UTF-8'));
    msg_out = s.start();
    headers={"Authorization":"Spake2 "+username+" "+base64.b64encode(msg_out).decode('UTF-8')};
    r=requests.get('http://127.0.0.1:8080/spake2-auth/', headers=headers);
    if r.status_code == 200:
        msg_in = base64.b64decode(r.headers["Authorization"].encode("UTF-8"));
        key = s.finish(msg_in);
#        print(r.text);
    else:
        print(r.headers);
else:
    print(r.headers);
