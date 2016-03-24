import requests;
from requests.auth import HTTPDigestAuth
from pythemis import scomparator;
import base64;

username = 'andrey';
password = 'password';


with requests.Session() as s:
    comparator=scomparator.scomparator(password.encode("UTF-8"));
    dd=base64.b64encode(comparator.begin_compare()).decode("UTF-8")
    headers = {"Authorization": "Themis "+username+" "+dd, "Connection":"Keep-Alive"};
    r = s.get('http://127.0.0.1:8080/themis-sc-auth/', headers=headers);
    if r.status_code == 308:
        dd = comparator.proceed_compare(base64.b64decode(r.headers["Authorization"].encode("UTF-8")));
        headers = {"Authorization": "Themis "+base64.b64encode(dd).decode("UTF-8")};
        r = s.get("http://127.0.0.1:8080//themis-sc-auth/index.html", headers=headers);
#        print(r.status_code);
        if r.status_code == 200:
            dd = comparator.proceed_compare(base64.b64decode(r.headers["Authorization"].encode("UTF-8")));
            if comparator.result() == scomparator.SCOMPARATOR_CODES.NOT_MATCH:
                print("error");
    else:
        print(r.headers);
