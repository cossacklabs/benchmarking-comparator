#
# Copyright (c) 2015 Cossack Labs Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#echo client with handmade ssession wrappers (see ssession_wrappers.py) 
#for none event handled transport, like plain socket
import socket;
import ctypes;
from pythemis import skeygen;
from pythemis import scomparator;
from pythemis import ssession;
import base64;




class transport(object):                                #callback object
    def __init__(self):
        self.socket=socket.socket();
        self.socket.connect(("127.0.0.1", 8080));

    def __dell__(self):
        self.socket.close();
        
    def send(self, message):                                #send callback
        self.socket.sendall(message);

    def receive(self, buffer_length):                        #receive callback
        a=self.socket.recv(buffer_length);
        print("recv", len(a));
        return a;

    def get_pub_key_by_id(self, user_id):                #necessary callback
        return user_id; 

transport_ = transport();
alg="EC";
obj = skeygen.themis_gen_key_pair(alg);
session=ssession.ssession(obj.export_public_key(), obj.export_private_key(), transport_);
data = session.connect();
while session.is_established() != True:
    data = session.receive();
print("session established");


comparator=scomparator.scomparator(b"password");
data=comparator.begin_compare()
session.send(("GET /themis-sc-auth/ HTTP/1.1\r\nUser-Agent: curl/7.38.0\r\nAuthorization: Themis andrey "+base64.b64encode(data).decode("UTF-8")+"\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\n\r\n").encode("UTF-8"));
headers= session.receive().decode("UTF-8").split('\r\n');
data = comparator.proceed_compare(base64.b64decode(dict(x.split(':') for x in headers[1:-4])["Authorization"]))
session.send(("GET /themis-sc-auth/ HTTP/1.1\r\nUser-Agent: curl/7.38.0\r\nAuthorization: Themis "+base64.b64encode(data).decode("UTF-8")+"\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\n\r\n").encode("UTF-8"));
headers= session.receive().decode("UTF-8").split('\r\n');
data = comparator.proceed_compare(base64.b64decode(dict(x.split(':') for x in headers[1:-6])["Authorization"]))

if comparator.result() == scomparator.SCOMPARATOR_CODES.NOT_MATCH:
    print("not match");
else:
    print("match");

