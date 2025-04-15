'''
- bn128 (Barreto-Naehrig) is a pairing-friendly elliptic curve.

- G1 is the base field of bn128 (F_p) with generator P.
- G2 is the extension field of bn128 (F_{p^2}) with generator P_hat.
- G_T is a subgroup of (F_{p^{12}}).
- |G_1| = |G_2| = p, and p is a prime of 255 bits.

- add, multiply are the functions for point addition and scalar multiplication in G1 and G2.
- e(.,.) is the bilinear pairing on G1 x G2 -> G_T.

- Z1, Z2 are the points at infinity for groups G1 and G2.
'''
import os 
try:
    from py_ecc.optimized_bn128 import (G1 as P, G2 as P_hat, multiply, add, pairing as e, curve_order as p, Z1, Z2)
    from py_ecc.fields import optimized_bn128_FQ12 as FQ12
except ImportError:
    print("Error: py_ecc is not installed. Please install it using 'pip install py-ecc'.")
    exit(1)

#-------------------------------- Helper functions --------------------------------
def inner_product(a, b):
    zero = Z1
    for i in range(len(a)):
        zero = add(zero, multiply(a[i], b[i]))
    return zero

def mod_inv(a, p):
    return pow(a, -1, p)

'''
r = (a_1/a_2, a_1/a_3, ..., a_1/a_l, a_2/a_3, a_2/a_4, ..., a_2/a_l, ..., a_{l-1}/a_l)
|r| = (l choose 2)
Mutual ratios remain invariant under scalar multiplication. Can be used to check equivalence classes.
'''
def mutual_ratios(a, p):
    r = []
    for i in range(len(a)):
        for j in range(i+1, len(a)):
            r.append((a[i] * mod_inv(a[j], p)) % p)
    return r

'''
Sample a random element from Z_p* using OS randomness (cryptographically secure).
OS somehow gathers entropy from places.
'''
def sample_Zp(p):
    rand_bytes = os.urandom(32)  # 256 bits of randomness
    rand_int = int.from_bytes(rand_bytes, byteorder='big') % (p - 1) + 1
    return rand_int

#-------------------------------- SPS_EQ class --------------------------------
class SPS_EQ:
    def __init__(self, l, P, P_hat, p):
        self.l = l
        self.P = P
        self.P_hat = P_hat
        self.p = p
        
    def keygen(self):
        self.sk = [sample_Zp(self.p) for _ in range(self.l)]
        pk = [multiply(self.P_hat, self.sk[i]) for i in range(self.l)]
        return self.sk, pk
    
    def sign(self, M):
        # ---- Membership / Length checks ----
        
        if(len(M) != self.l):
            raise ValueError(f"Message length must be equal to vector length, l: {self.l}")
        
        for M_i in M:
            if(M_i == Z1 or multiply(M_i, self.p) != Z1):
                raise ValueError(f"{M_i} is not an element of G_1^*")
            
        # -------------------------------------
        y = sample_Zp(self.p) 

        Z = multiply(inner_product(M, self.sk), y)

        Y = multiply(self.P, mod_inv(y, self.p))

        Y_hat = multiply(self.P_hat, mod_inv(y, self.p))

        sigma = (Z, Y, Y_hat)

        return sigma
    
    def verify(self, M, sig, pk):

        Z, Y, Y_hat = sig

        # ---- Membership / Length checks ----
        if(len(M) != self.l):
            raise ValueError(f"Message length must be equal to vector length, l: {self.l}")
        
        for M_i in M:
            if(M_i == Z1 or multiply(M_i, self.p) != Z1):
                raise ValueError(f"{M_i} is not an element of G_1^*")
            
        for X in pk:
            if(X == Z2 or multiply(X, self.p) != Z2):
                raise ValueError(f"{X} is not an element of G_2^*")
            
        if(Z != Z1 and multiply(Z, self.p) != Z1):
            raise ValueError(f"{Z} is not an element of G_1")
        
        if(Y == Z1 or multiply(Y, self.p) != Z1):
            raise ValueError(f"{Y} is not an element of G_1^*")
        
        if(Y_hat == Z2 or multiply(Y_hat, self.p) != Z2):
            raise ValueError(f"{Y_hat} is not an element of G_2^*")
        
        # -----------------------

        # Check 1: 
        e_1 = FQ12.one()
        for i in range(self.l):
            e_1 = e_1 * e(pk[i], M[i])

        e_2 = e(Y_hat, Z)
        
        if(e_1 != e_2):
            return 0
            
        # Check 2:
        e_3 = e(self.P_hat, Y)
        e_4 = e(Y_hat, self.P)
        
        return 1 if e_3 == e_4 else 0
    

    def chgRep(self, M, sigma, mu, pk):
    
        if(self.verify(M, sigma, pk) == 0):
            raise ValueError("Invalid signature")
    
        Z, Y, Y_hat = sigma

        psi = sample_Zp(self.p)

        sigma_prime = (
            multiply(Z, (psi * mu) % self.p), 
            multiply(Y, pow(psi, -1, self.p)),  
            multiply(Y_hat, pow(psi, -1, self.p))
        )
        return sigma_prime
    
    def vKey(self, pk):
        if(len(pk) != self.l):
            raise ValueError(f"Public key length must be equal to vector length, l: {self.l}")
        for i in range(self.l):
            if(pk[i] != multiply(self.P_hat, self.sk[i])):
                return 0
        return 1

# Print the order of G1 and G2
if __name__ == "__main__":
    print("Curve order: ")
    print(p)
    print()
    
    print("P (Generator for G1): ")
    print(P)
    print()
    
    print("Z1 (Point at infinity for G1): ")
    print(Z1)
    print()
    
    print("P_hat (Generator for G2): ")
    print(P_hat)
    print()
    
    print("Z2 (Point at infinity for G2): ")
    print(Z2)
    print()

    l = 2
    SPS_EQ = SPS_EQ(l, P, P_hat, p)
    sk, pk = SPS_EQ.keygen()
    print("Secret key: ")
    print(sk)
    print()
    
    print("Public key: ")
    print(pk)
    print()
    
    a = [sample_Zp(p) for _ in range(l)]
    M = [multiply(P, a[i]) for i in range(l)]
    print("Message: ")
    print(M)
    print()
    
    print("Mutual ratios: ")
    print(mutual_ratios(a, p))
    print()
 
    sigma = SPS_EQ.sign(M)
    print("Signature: ")
    print(sigma)
    print()
    
    # Try verification
    try:
        result = SPS_EQ.verify(M, sigma, pk)
        print("Verification result: ")
        print(result)
        print()
    except Exception as e:
        print("Verification error: ")
        print(e)
        print()
    
    garbage_pk = [multiply(P_hat, sample_Zp(p)) for _ in range(l)]
    print("Vkey with garbage pk: ")
    print(SPS_EQ.vKey(garbage_pk))
    print()
    
    try:
        b = SPS_EQ.verify(M, sigma, garbage_pk)
        print("Verification with garbage pk: ")
        print(b)
        print()
    except Exception as e:
        print("Verification error: ")
        print(e)
        print()
    
    mu = sample_Zp(p)
    a_prime = [a[i] * mu for i in range(l)]
    M_prime = [multiply(P, a_prime[i]) for i in range(l)]
    print("Transformed Message by: ")
    print(mu)
    print(M_prime)
    print()
    
    print("Mutual ratios: ")
    print(mutual_ratios(a_prime, p))
    print()
    
    print("Mutual ratios equal?: ")
    print(mutual_ratios(a, p) == mutual_ratios(a_prime, p))
    print()
    
    sigma_prime = SPS_EQ.chgRep(M, sigma, mu, pk)
    print("sigma_prime: ")
    print(sigma_prime)
    print()
    
    try:
        b = SPS_EQ.verify(M_prime, sigma_prime, pk)
        print("Verification result with new signature: ")
        print(b)
        print()
    except Exception as e:
        print("Verification error: ")
        print(e)
        print()
    

