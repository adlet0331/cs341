import os
import json
import random
repeat = 100
for i in range(repeat):
    seed = random.randrange(1, 100000)
    print(f'i={i+1} seed={seed}')
    os.system(f'RANDOM_SEED={seed} ./build/app/kens/test-kens-all-unreliable --gtest_filter=-TestEnv_Congestion* --gtest_output=json:asdf.json > asdf.txt')
    with open('asdf.json') as file:
        data = json.load(file)
        if(data['failures'] > 0):
            print("!!!")
            break