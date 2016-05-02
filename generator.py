import re
import string
import random
import subprocess
from os import walk, remove
from os.path import join

def gen_voters(unreg=False):
    n = int(input("Enter how many registered voters to generate\n"))
    
    first_names = []
    last_names = []
    people = []

    fp = open('yob1880.txt')
    

    for line in fp:
        temp = re.split('\W+', line)[0]
        first_names.append(temp)
    fp.close()

    fp = open('last_names.txt')
    for line in fp:
        temp = re.split('\W+', line)[0].capitalize()
        last_names.append(temp)
    fp.close()

    if unreg:
        people.append((first_names[0], last_names[0]))
        return people
    
    fp = open('reg_voters.txt', 'w')
    i = 0
    while i < n:
        temp = (random.choice(first_names), random.choice(last_names))
        print(temp[1] + ", " + temp[0] , "", '', file=fp)
        people.append(temp)
        i+=1
    
    fp.close()
    return people
    

def gen_keys(voters, unreg=False):
    i = 0
    dr = 'auth/voters'
    
    for person in voters:
        if unreg:
            outfile = join(dr, "unreg-key-" + str(i) + ".pem")
        else:
            outfile = join(dr, "key-" + str(i) + ".pem")
        subprocess.check_call(["openssl", "genpkey", "-algorithm", "RSA", "-out", outfile])
        i+= 1

def del_voters():
    dr = 'auth/voters'
    for root, dirs, files in walk(dr):
        for name in files:
            remove(join(root,name))

def gen_certs(voters, eve=False, unreg=False):
    dr = 'auth'
    if eve:
        ca_cert = join(dr, 'eve-cert.pem')
        ca_key = join(dr, 'eve-key.pem')
        ca_serial = join(dr, 'eve-cert.srl')
    else:
        ca_cert = join(dr, 'ca-cert.pem')
        ca_key = join(dr, 'ca-key.pem')
        ca_serial = join(dr, 'ca-cert.srl')
    i = 0

    k = 'key-'
    cs = 'csr'
    ce = 'cert'
    
    if unreg:
        key = 'unreg-' +  k
        csr = 'unreg-' + cs
        cert = 'unreg-' +  ce
    else:
        key = k
        csr = cs
        cert = ce

    for people in voters:
        v_key = join(dr, 'voters', key + str(i) + '.pem')
        v_csr = join(dr, 'voters', csr + str(i) + '.pem')
        v_cert = join(dr, 'voters', cert + str(i) + '.pem')
        
        csr_opt = "/CN=" + people[1] + ", " + people[0]
        
        subprocess.check_call(
                ["openssl", "req", "-new", 
                "-key", v_key,
                "-out", v_csr,
                "-subj", csr_opt ])
        subprocess.check_call(
                ["openssl", "x509", "-req", 
                "-CA", ca_cert,
                "-CAkey", ca_key, 
                "-CAserial", ca_serial,
                "-in", v_csr, 
                "-out", v_cert])
        remove(v_csr)
        i+=1
