import re
import string
import random

def gen_names():
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
