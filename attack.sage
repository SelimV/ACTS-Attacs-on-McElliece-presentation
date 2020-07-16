# Application of Coding Theory to Security
# Project: Attacks against McEliece

reset()
import random
import time
set_random_seed(0)
random.seed(0)
loc = '~/Documents/ACTS/Project/attack.sage' 

print('--- Random selection attack against McEliece cryptosystem ---')

m = 10
q = 2^m
n = 2^(m-1) 
t = 43
F.<a> = GF(q)
R.<x> = F[x]
L = F.list()[:n]
g = R.irreducible_element(t)
C = codes.GoppaCode(g,L)
G = C.generator_matrix()
k = C.dimension()
print('Encoding: ' + str(C))

S = random_matrix(GF(2), k, k)
while S.is_singular():
    S = random_matrix(GF(2), k, k)

SG = SymmetricGroup(n)
P = matrix(GF(2), Permutation(SG.random_element()).to_matrix())
M = S*G*P

m_bin = random_vector(GF(2), k)
print('Message to be encoded: ' + str(m_bin))

# Encode the message
Chan = channels.StaticErrorRateChannel(C.ambient_space(), t)
c = Chan(m_bin*M)

print()

# Attack! (Not really smart)
indices = range(n)
Mt = M.transpose()
counter0 = 1
print('Starting the basic attack...')
start = time.time()

while True:
    rand_indices = random.sample(indices, k)
    Mk = matrix(GF(2), [Mt[i] for i in rand_indices]).transpose()

    while rank(Mk) != k:
        rand_indices = random.sample(indices, k)
        Mk = matrix(GF(2), [Mt[i] for i in rand_indices]).transpose()

    ck = vector(GF(2), [c[i] for i in rand_indices])
    Mk_inv = Mk.inverse()
    mg = ck * Mk_inv
    if (c + mg * M).hamming_weight() <= t:
        break

    counter0 += 1
    if counter0 % 500 == 0: print(counter0)

time_taken0 = time.time() - start
if mg == m_bin:
    print('Attack successful!')
    print('Number of iterations for the basic attack: ' + str(counter0))
    print('Time taken for the basic attack: ' + str(time_taken0) + ' seconds')
else:
    print('Something went wrong!')


print()

# Attack! (Smart)
indices = range(n)
Mt = M.transpose()
counter_smart = 1
print('Starting the generalized attack (j = 2)...')
start = time.time()
succeed = True

while succeed:
    rand_indices = random.sample(indices, k)
    Mk = matrix(GF(2), [Mt[i] for i in rand_indices]).transpose()

    while rank(Mk) != k:
        rand_indices = random.sample(indices, k)
        Mk = matrix(GF(2), [Mt[i] for i in rand_indices]).transpose()

    ck = vector(GF(2), [c[i] for i in rand_indices])
    Mk_inv = Mk.inverse()
    MM = Mk_inv * M

    # Weight 0 pattern
    check0 = c + ck * MM
    if check0.hamming_weight() <= t:
        mg = ck * Mk_inv
        succeed = False
        break

    # Weight 1 pattern
    i = 0
    while i < k and succeed:
        check1 = check0 + MM[i]

        if check1.hamming_weight() <= t:
            ck[i] += 1
            mg = ck * Mk_inv
            succeed = False
            break

        # Weight 2 pattern
        j = i+1
        while j < k and succeed:
            check2 = check1 + MM[j]

            if check2.hamming_weight() <= t:
                ck[i] += 1
                ck[j] += 1
                mg = ck * Mk_inv
                succeed = False
                break

            j += 1

        i += 1

    counter_smart += 1
    if counter_smart % 500 == 0: print(counter_smart)

time_taken_smart = time.time() - start
if mg == m_bin:
    print('Attack successful!')
    print('Number of iterations for the basic attack: ' + str(counter_smart))
    print('Time taken for the basic attack: ' + str(time_taken_smart) + ' seconds')
else:
    print('Something went wrong!')
