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

    i = 0
    while i < n:
        temp = (random.choice(first_names), random.choice(last_names))
        people.append(temp)
        i+=1
    return people

def gen_keys(voters):
    i = 0
    
    for person in voters:
        outfile = "auth/voters/key-" + str(i) + ".pem"
        subprocess.check_call(["openssl", "genpkey", "-algorithm", "RSA", "-out", outfile])
        i+= 1

def del_keys():
    dr = 'auth/voters'
    for root, dirs, files in walk(dr):
        for name in files:
            remove(join(root,name))

