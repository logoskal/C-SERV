import os
from random import randint
import random

def randomizer(start=0, end=1, bias=None):
    if bias == 0:
        return random.choices(range(start, end), [1/(i+1) for i in range(start, end)])[0]
    elif bias == 1:
        return random.choices(range(start, end), [i for i in range(start, end)])[0]

for day in range(227, 270):
    for commits in range(0, randint(3, 40)):
        day = str(day)+' days ago'
        with open('file.txt', 'a')as file:
            file.write(day)
        os.system('git add .')
        os.system('git commit --date="'+day+'" -m "commit"')
os.system('git push -u origin main ')
