# Application of Coding Theory to Security
# Project: Attacks against McEliece

reset()
loc = '~/Documents/ACTS/Project/attack.sage' 

m = 10
q = 2^m
n = 2^9
t = 23
F.<a> = GF(q)
R.<x> = F[x]
L = F.list()[:n]
g = R.irreducible_element(t)
C = codes.GoppaCode(g,L)
G = C.generator_matrix()
k = C.dimension()
print(C)

S = random_matrix(GF(2), k, k)
while S.is_singular():
    S = random_matrix(GF(2), k, k)

SG = SymmetricGroup(n)
P = matrix(GF(2), Permutation(SG.random_element()).to_matrix())
M = S*G*P

message = random_vector(GF(2), k)

# Encode the message
Chan = channels.StaticErrorRateChannel(C.ambient_space(), t)
c = Chan(message*M)

# Attack!
