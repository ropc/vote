import re
import string
import random
import subprocess
from os import walk, remove
from os.path import join

def gen_voters():
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

    fp = open('reg_voters.txt', 'w')

    i = 0
    while i < n:
        temp = (random.choice(first_names), random.choice(last_names))
        print(temp[1] + ", " + temp[0] , "", '', file=fp)
        people.append(temp)
        i+=1
    
    fp.close()
    return people
    

def gen_keys(voters):
    i = 0
    dr = 'auth/voters'
    
    for person in voters:
        outfile = join(dr, "key-" + str(i) + ".pem")
        subprocess.check_call(["openssl", "genpkey", "-algorithm", "RSA", "-out", outfile])
        i+= 1

def del_voters():
    dr = 'auth/voters'
    for root, dirs, files in walk(dr):
        for name in files:
            remove(join(root,name))

def gen_certs(voters):
    dr = 'auth'
    ca_cert = join(dr, 'ca-cert.pem')
    ca_key = join(dr, 'ca-key.pem')
    ca_serial = join(dr, 'ca-cert.srl')
    i = 0

    for people in voters:
        v_key = join(dr, 'voters', 'key-' + str(i) + '.pem')
        v_csr = join(dr, 'voters', 'csr-' + str(i) + '.pem')
        v_cert = join(dr, 'voters', 'cert-' + str(i) + '.pem')
        
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

def sign_csrs():
    dr = 'auth/voters'
    ca_cert = 'auth/ca-cert.pem'
    ca_key = 'auth/ca-key.pem'

    for root, dirs, files in walk(dr):
        for name in files:
            if 'csr' in name:
                subprocess.check_call(
                        ["openssl", "x509", "-req", 
                        "-CA", ca_cert,
                        "-CAkey", ca_key, 
                        "-CAcreateserial",
                        "-in", join(root, name), 
                        "-out", join(root, 'cert' + name[3:])])
