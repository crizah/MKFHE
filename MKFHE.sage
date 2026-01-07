
import random
import time

lamda = 84  
m = 1024
n = euler_phi(m)    #deg(f)
f = cyclotomic_polynomial(m)
R.<x> = PolynomialRing(ZZ)  
Rq = QuotientRing(R, f)     #ℤ[x]/(f(x))
q = 12289     #prime, small and noise??
Zq = Integers(q)
Rq_mod = QuotientRing(PolynomialRing(Zq, 'x'), f) # implemetation of Rq in code 

k = 3
B = [Rq_mod.random_element() for _ in range(k)]
a_star = Rq_mod.random_element()

standard_key_generation_parameters = (a_star, B)

# print("Cyclotomic polynomial f(x):", f)
# print("Degree of f(x):", f.degree())
# print("Modulus q:", q)
# print("Shared public parameters B:", B)
# print("Shared mask a*:", a_star)
# print("done")



def secret_key_generation():
    # secret key generation for m users
    # by Ui
    
    si = Rq_mod.random_element()
    return si



# fix the ieterations its supposed to depend on who runs the algo

def sample_error():
    # small noise distribution from -3 to 3
    # ei
    coeffs = [random.randint(-3, 3) for _ in range(n)]
    return Rq_mod(R(coeffs))

def public_key_generation(si , i, key_generation_parameters, e_list):

    # public key generation for m users
    # pki = (bi, a∗) = ([a∗(Bisi) + ei]q, −a∗) where, ei ← χ is small error polynomial.
    # run by user

    a_star, B = key_generation_parameters
    Bi = B[i]  # handle case where k < m
    ei = sample_error()
    e_list.append(ei)
    bi = a_star * Bi * si + ei   
    pk_i = (bi, -a_star)
    

    return pk_i


    
def group_publlic_key_generation(public_keys, k):

    # the modq is taken care of with Rq_mod

    a = Rq_mod(0)

    for i in range(k):
        a += public_keys[i][0]
        
    gpk = (a, -public_keys[0][1])

    return gpk
    



def encrypt_message(message, gpk, q, t):
    delta = q // t  # scaling factor for plaintext

    # do e0 and e1 belong to the e_list, ask for the consistency of the e_list


    # Embed message into Rq by scaling and converting
    v = sample_error()
    e0 = sample_error()
    e1 = sample_error()
    message_scaled = Rq_mod(message) * delta  # m must be a small poly in ZZ[x]

    # Compute ciphertext components
    c0 = v * gpk[0] + message_scaled + e0
    c1 = v * gpk[1] + e1
    ct = (c0, c1)

    return ct
    
# ask e*j, Lj, E in auxilliary, if e*j is the same as ei

def partial_decryption_key(ct, sj, j):
    # pdkj = [c1Bjsj + e∗j]
    c1 = ct[1]
    Bj = B[j]
    e_star_j = sample_error()
    pdkj = c1*Bj*sj + e_star_j

    return pdkj




def full_decryption(ct, partial_decryption_keys, k):
   
    pdkj_summation = Rq_mod(0)

    for i in range(k):
        pdkj_summation += partial_decryption_keys[i]
    
    message = (ct[0] + pdkj_summation)
    return message


def auxiliary_key_one(sj, j, B_list , gpk, q, t, w):

    # Rj [0] = (E(wl(sjBj )2))⌊logw(q)⌋

    log_bound = floor(log(q, w))
    Bj = B_list[j]

    base_poly = (sj * Bj)^2
    Rj_0 = [encrypt_message(Rq_mod(base_poly * w^l), gpk, q, t) for l in range(log_bound + 1)]
    
    # Rj [1] = (E(wl2sjLiLj ))⌊logw(q)⌋
    Rj_1 = []
    for i, Bi in enumerate(B_list):
        if i == j:
            continue
        inner_poly = 2 * sj * Bj * Bi

        encrypted_slots = [encrypt_message(Rq_mod(inner_poly * w^l), gpk, q, t) for l in range(log_bound + 1)]
        # print(len(encrypted_slots))
        Rj_1.append(encrypted_slots)
    
    return (Rj_0, Rj_1)


def auxiliary_key_two(sj, R_list, q, w):

    # R[2] = (sj ∗ E(wl ∗ 2siLiLj )) + ej )⌊logw(q)⌋
    # Rj [1] = (E(wl2sjLiLj ))⌊logw(q)⌋

    

    log_bound = floor(log(q, w))
    Rj_2 = []

    for i in range(len(R_list)):  
        encrypted_list = R_list[i]
        Rj2_i = []

        for l in range(log_bound + 1):
            Ri = encrypted_list[0][l]
            # print(type(Ri))
            # print(len(Ri))
            Ri_0, Ri_1 = Ri

            R2_0 = sj * Ri_0
            R2_1 = sj * Ri_1

            
            R2_0 += sample_error()
            R2_1 += sample_error()

            # R2_i = (sj * Ri) + sample_error()
            yeah = (R2_0, R2_1)
            Rj2_i.append(yeah)

        Rj_2.append(Rj2_i)

    return Rj_2


def calculate_Q(R2_list, q, w):
    log_bound = floor(log(q, w))
    k = len(R2_list)
    
   
    Q = [(Rq_mod.zero(), Rq_mod.zero()) for _ in range(log_bound + 1)]

    for i in range(k):
        for j in range(i+1, k):
            Rij = R2_list[j][i]  # Note: R2[j][i] is for i ≠ j
            for l in range(log_bound + 1):
                c0, c1 = Rij[l]
                q0, q1 = Q[l]

                Q[l] = (q0 + c0, q1 + c1)

    return Q

def calculate_P(R_list, q, w):
    log_bound = floor(log(q, w))
    

    P = [(Rq_mod.zero(), Rq_mod.zero()) for _ in range(log_bound + 1)]

    for Rj_0, _ in R_list: 
        for l in range(log_bound + 1):
            cj0, cj1 = Rj_0[l]
            pj0, pj1 = P[l]
            P[l] = (pj0 + cj0, pj1 + cj1)

    return P

def rlk_generation(R_list, R2_list, q, w):
    # P = {Pki=1 E(wl(Bisi)2)}⌊logw(q)⌋
    # summation of r_list_0 of all users
    P = calculate_P(R_list, q, w)

    # Q = homomorphic addition of elemnts in R2 where 1<=i<=j
    Q = calculate_Q(R2_list, q, w)
    rlk = P + Q
    return rlk




def addition(ct1, ct2):
    c_sum = (ct1[0] + ct2[0], ct1[1] + ct2[1])

    return c_sum


def multiplication(ct1, ct2):
# For any two ciphertexts c1 = (c10, c11) and c2 =
# (c20, c21),
# cmul = (d0, d1, d2)
# where, d0 = c10.c20, d1 = c10.c21 +c11.c20, d2 = c11.c21
    d0 = ct1[0] * ct2[0]
    d1 = ct1[0] * ct2[1] + ct1[1]*ct2[0]
    d2 = ct1[1] * ct2[1]
    return (d0, d1, d2)

def multiplication_afterRLK(x, P, Q):
    # crel = (c′0, c′1) = (d0 + k1.d2, d1 + k2.d2)

    d0, d1, d2 = x

    p_sum0, p_sum1 = Rq_mod.zero(), Rq_mod.zero()
    q_sum0, q_sum1 = Rq_mod.zero(), Rq_mod.zero()

    for (p0, p1), (q0, q1) in zip(P, Q):
        p_sum0 += d2 * p0
        p_sum1 += d2 * p1
        q_sum0 += d2 * q0
        q_sum1 += d2 * q1

    c0 = d0 + p_sum0
    c1 = d1 + q_sum0

    return (c0, c1)



secret_keys = [] 
public_keys = [] # available to all users
e_list = []


for i in range(k):
    # all users run this to get their secret and public keys
    si = secret_key_generation()
    secret_keys.append(si)

    pk_i = public_key_generation(si, i, standard_key_generation_parameters, e_list)
    public_keys.append(pk_i)



print("secret key generation done")
print("public key generation done")

gpk = group_publlic_key_generation(public_keys, k) # this is also run by all the users

print("group public key generation is done")

# messages = R([0]) for 0, R([1]) for 1, R([1,1]) for x+1, R([0, 1, 1]) for x^2+x, R([1, 1, 0, 1]) for x^3+x+1

t = 2  # 2 if binary message
pt1 = Rq_mod(R([1, 1]))  # x + 1
pt2 = Rq_mod(R([0, 1, 1]))  # x^2 + x
# pt3 = Rq_mod(R([1, 1, 0, 1])) # x^3 + x + 1

# plaintext_list = (pt1, pt2, pt3) 

partial_decryption_keys = [] # available to all users

cipher_texts = []

for j in range(k):
    # all users run this to encrypt a plain text and generate partial decryption key
    # ptj = plaintext_list[j]
    # pt_sum = pt1 + pt2 

    ct1 = encrypt_message(pt1, gpk, q, t)
    # cipher_texts.append(ctj)
    # ct1 = encrypt_message(pt1, gpk, q, t)
    # ct2 = encrypt_message(pt2, gpk, q, t)
    
    pdkj = partial_decryption_key(ct1, secret_keys[j], j)
    cipher_texts.append(ct1)   
    partial_decryption_keys.append(pdkj)


print("encryption is completed")
print("partial decryption keys are generated")


# c_sum = addition(cipher_texts[0], cipher_texts[1])

# decrypted_c_sum = full_decryption(c_sum, partial_decryption_keys, k)

# pt_sum = pt1 + pt2
# if(pt_sum == decrypted_c_sum):

#     print("decryption is correct")
# else:
#     print("kys")

ct1 = encrypt_message(pt1, gpk, q, t)

# ct1_decrypted = full_decryption(ct1, partial_decryption_keys, k)
# if(ct1_decrypted == pt1):
#     print("god pls")
# else:
#     print("they trynna drown me in this hoe")


# m1 = full_decryption(cipher_texts[0], partial_decryption_keys, k)
# m2 = full_decryption(cipher_texts[1], partial_decryption_keys, k)
# m3 = full_decryption(cipher_texts[2], partial_decryption_keys, k)

# pt_sum = pt1 +pt2 + pt3

# enc_pt_sum = encrypt_message(pt_sum, gpk, q, t)

# if (c_sum == enc_pt_sum):
#     print("homomorphic yeah")
# else:
#     print("need to look up further")

# m_sum = full_decryption(c_sum, partial_decryption_keys, k)


# delta = q // t
# expected_sum = Rq_mod((pt1 + pt2 + pt3) * delta)


# if expected_sum == m_sum:
#     print("Homomorphic addition verified after decryption")
# else:
#     print("Homomorphic addition failed")

# if m1 + m2 == m_sum:
#     print("Homomorphic addition verified after decryption")
# else:
#     print("Homomorphic addition failed")

w = 2

R_list = []
for j in range(k):
    # aux key generation for each user
    sj = secret_keys[j]
    R_j = auxiliary_key_one(sj, j, B, gpk, q, t, w)
    R_list.append(R_j)


print("aux key 1 generation is done")

R2_list = []
for j in range(k):
    sj = secret_keys[j]
    Rj1 =  R_list[j]
    Rj2 = auxiliary_key_two(sj, R_list, q, w)
    R2_list.append(Rj2)
    
print("aux key 2 generation is done")

rlk = rlk_generation(R_list, R2_list, q, w)
print("rlk generation is done")



ct2 = encrypt_message(pt2, gpk, q, t)
# intermediate_mul = multiplication(ct1, ct2)
P = calculate_P(R_list, q, w)
Q = calculate_Q(R2_list, q, w)
# mul_value = multiplication_afterRLK(intermediate_mul, P, Q)
# print("multiplication is done")






# start_time_add = time.time()
# for i in range(1000000):
#     c_sum = addition(ct1, ct2)

# end_time_add = time.time()
# print("addition time is ", end_time_add - start_time_add)


# start_time_en = time.time()
# for i in range(1000000):
#     ct = encrypt_message(pt1, gpk, q, t)

# end_time_en = time.time()
# print("encryption time is ", end_time_en - start_time_en)



# start_time_mul = time.time()
# for i in range(1000000):
#     intermediate_mul = multiplication(ct1, ct2)
#     mul_value = multiplication_afterRLK(intermediate_mul, P, Q)
# end_time_mul = time.time()

# print("time taken for multiplication is ", end_time_mul - start_time_mul)

# start_time_de = time.time()
# for i in range(1000000):
#     yeah  = full_decryption(ct1, partial_decryption_keys, k)
    

# end_time_de = time.time()
# print("decryption time is  ", end_time_de - start_time_de)


s = time.time()
count = 0
duration = 60  # seconds (1 minute)

while time.time() - s < duration:
    c_sum = addition(ct1, ct2)
    count += 1


print(f"addition ran {count} times in 1 minute.")
print(f"Average calls per second: {count / 60:.2f}")

e = time.time()
cs = 0
d = 60

while time.time() - e < d:
    ct = encrypt_message(pt1, gpk, q, t)
    
    cs += 1


print(f"encryption ran {cs} times in 1 minute.")
print(f"Average calls per second: {cs / 60:.2f}")


f = time.time()
g = 0
du = 60
while time.time() - f < du:
    intermediate_mul = multiplication(ct1, ct2)
    mul_value = multiplication_afterRLK(intermediate_mul, P, Q)
    
    g += 1


print(f"encryption ran {g} times in 1 minute.")
print(f"Average calls per second: {g / 60:.2f}")


j = time.time()
h = 0
eee = 60
while time.time() - j < eee:
    yeah  = full_decryption(ct1, partial_decryption_keys, k)
    h += 1


print(f"encryption ran {h} times in 1 minute.")
print(f"Average calls per second: {h / 60:.2f}")



