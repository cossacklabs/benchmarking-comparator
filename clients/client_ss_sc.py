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
import ssession_wrappers;
import socket;
import ctypes;
from pythemis import skeygen;
from pythemis import scomparator;



class transport(object):                                #callback object
    def __init__(self):
        self.socket=socket.socket();
        self.socket.connect(("127.0.0.1", 1234));

    def __dell__(self):
        self.socket.close();
        
    def send(self, message):                                #send callback
        self.socket.sendall(message);

    def receive(self, buffer_length):                        #receive callback
        a=self.socket.recv(buffer_length);
        return a;

    def get_pub_key_by_id(self, user_id):                #necessary callback
        return user_id; 

transport_ = transport();
alg="EC";
obj = skeygen.themis_gen_key_pair(alg);
private_key = obj.export_private_key();
public_key = obj.export_public_key();
session=ssession_wrappers.ssession_client(public_key, private_key, transport_);

comparator=scomparator.scomparator(b"password");
data=comparator.begin_compare()

while comparator.result() == scomparator.SCOMPARATOR_CODES.NOT_READY:
    session.send(data);
    data=comparator.proceed_compare(session.receive());

if comparator.result() == scomparator.SCOMPARATOR_CODES.NOT_MATCH:
    print("not match");
else:
    print("match");

