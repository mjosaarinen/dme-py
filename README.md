# dme-py

2023-07-25  Markku-Juhani O. Saarinen  mjos@pqshield.com

A DME-Sign (Level-1) implementation in Python and a PoC for a forgery attack. DME-Sign is a candidate algorithm in the [NIST Call for additional PQC Signatures](https://csrc.nist.gov/Projects/pqc-dig-sig/round-1-additional-signatures).

###	Testing the implementation

The main implementation file `dme.py` contains NIST KAT testing code: running `python3 dme.py` should generate output matching `PQCsignKAT_369.rsp` in the submission file (and also locally in the KAT directory). Emulation of the NIST test suite DRBG is needed for KATs; this is provided by `aes_drbg.py`.

```
$ python3 dme.py
# dme-3rnds-8vars-32bits-sign

count = 0
seed = 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7..
mlen = 33
msg = D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC..
pk = F7622FD50470D252250B56633EFDDC987865743E99D7F5CA360FAC5D8CB9A93A59..
sk = BEB110F179E879037A24857F41AE9E6274C67808AD47400F6EDF56894B1ABE6F02..
smlen = 65
sm = D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8..
```

##	Fast Inversion demo

The multivariate candidate DME-Sign has three submitted parameter sets, q in {2^32,2^48,2^48} for NIST security targets I, III, and V. In the following discussion, I will concentrate on the "32-bit" level I version. We will describe a 2^-96 complexity forgery attack on it.

DME-Sign is built on a "trapdoor function" (in the style of RSA); there is a secret mapping from 256 bits to 256 bits (used for creating signatures) and a matching public mapping which is its inverse (for verifying signatures).

The file `invert_demo.py` demonstrates how to invert half of this mapping quickly; given a public key and a target for the first 128 bits of the "secret" side of the permutation, it selects 128 bits in the signature side that matches it.
```
$ python3 invert_demo.py 
=== count =  0
m1 =  060a1e26 6cb1fe61 0ba18e4c 1b9a410b 8e1c10e0 a3417574 140bcf0a 159b1899
m2 =  060a1e26 6cb1fe61 0ba18e4c 1b9a410b 8e1c10e0 a3417574 140bcf0a 159b1899
[OK] simplified mapping match.
m3 =  53579029 d9eb70e6 08090a0b 0c0d0e0f 7cb8b25e 4de5ac5c 142325cb 7b5bda96
[OK] linear mapping to m[2:4]
sv =  fe9c5602 108eb7c6 00000000 00000000 0b0d9ad1 be13a58c 01234567 89abcdef
m4 =  00010203 04050607 08090a0b 0c0d0e0f 7cb8b25e 4de5ac5c 142325cb 7b5bda96
[OK] Half of function inverted!
```
The same public keys are generated as in the KAT test vectors. The first comment, "simplified mapping match," indicates that the simplified algebraic description (below) is working fine -- the final comment indicates that the first 128 bits of the result of "public key verification" are set to target value 000102..0e0f in the trapdoor function. This has also been verified against the reference C implementation.


###	Observation on invertibility

The DME trapdoor function is based on computations in binary field Fq. Public mapping boils down to the evaluation of multivariate polynomials whose coefficients are defined by the public key. The input variables come from the signature.

The input and output for the public key mapping is a vector of eight 32-bit field elements. I prefer zero-based indexing, so I write the signature variables as (s[0], s[1], .. s[7]) and verification (message) variables as (m[0], m[1], .. m[7]). Apologies -- the technical specification document `Implementation of DME-3rnds-8vars-32bits-sign.pdf` indexes signature variables from x1 to x8.

We observe that setting signature words s[2]=0 and s[3]=0 (x3=x4=0 in the equations of the paper) causes a vast majority of the monomials in the public mapping to vanish, massively simplifying the mapping. There are other options with similar effects.

Let t(i) denote some power-of-2 exponentiation of signature word i -- s[i]^(2^f) for some power f defined the public key. Since this is a binary field, we have (x+y)^2 = x^2 + y^2, and squaring is bitwise linear (DME is "bitwise multilinear."). Hence t(i) is a constant linear combination of bits in s[i], defined by the public key.

With the setting t(2)=t(3)=0, the dependencies in the public mapping can be expressed as a function of a subset of multivariate polynomial coefficients a[], b[], c[], d[] in the public key and linear combinations of signature bits as:

m[0..1] = a[4]*t(6)*t(4)*t(0) + a[9]*t(7)*t(4)*t(0) + a[14]*t(6)*t(5)*t(0) + a[19]*t(7)*t(5)*t(0) + a[24]*t(0) + a[27]*t(6)*t(4)*t(1) + a[30]*t(7)*t(4)*t(1) +
 a[33]*t(6)*t(5)*t(1) + a[36]*t(7)*t(5)*t(1) + a[39]*t(1) + a[44]*t(6)*t(4) +
 a[49]*t(7)*t(4) + a[54]*t(6)*t(5) + a[59]*t(7)*t(5) + a[64]

m[2..3] = b[20]*t(6)*t(4) + b[21]*t(7)*t(4) + b[22]*t(6)*t(5) + b[23]*t(7)*t(5) + b[24]
 
m[4..5] = c[20]*t(6)*t(4) + c[21]*t(7)*t(4) + c[22]*t(6)*t(5) + c[23]*t(7)*t(5) + c[24]

m[6..7] = d[52]*t(6)*t(4) + d[53]*t(7)*t(4) + d[54]*t(6)*t(5)*t(4) + d[55]*t(7)*t(5)*t(4) + d[56]*t(4) + d[57]*t(6)*t(5) + d[58]*t(7)*t(5) +  d[59]*t(5) + d[60]*t(6)*t(4) + d[61]*t(7)*t(4) + d[62]*t(6)*t(5) + d[63]*t(7)*t(5) + d[64]

Here m[0..1] means that the mapping for m[0] and m[1] is of the same form with the same input variables; the public key coefficients a[] for m[0] and m[1] are different. Similarly, for the other three word pairs m[2..3], m[4..5], m[6..7].

## Simple 2^96 Forgery

Each randomized trial for forgery of some "msg" under a given public key first proceeds just like the signing function:

1. msg = {0,1)^* input message
2. r[0:8] = pick a random 64-bit salt
3. w[0:16] = SHA3(msg || r), with 128-bit w result (yep)
4. g[0:16] = SHA3(w[0:16]) 
   g[0:8] ^= r[0:8]  # we XOR r on the lower half of g
5. We turn 256-bit (w || g} into eight 32-bit target words m[i] 

### Forgery steps:

Or forged signatures are of form [ s0, s1, 0, 0, s4, s5, s6, s7 ], with s[2] and s[3] set to zeros.

1. We first select s[4..7] so that m[2..5] will have the desired value. The demo forces only m[2..3] and treats s[6..7] as constants -- thereby turning a bilinear equation into a linear one and allowing efficient solution. For this attack, we assume that with at most 2^96 offline effort (e.g., a table), we succeed in the 128-bit inversion with probability 2^-32.

2. We then treat m[6..7] as constants. Now the equations for m[0..1] are linearized as a function of s[0..1] (just like in the demo) and can be solved easily. Changing s[s..1] does not affect the already solved m[2..5] target values.

3. We have forced 192 bits to the target -- as much as one can hope with s[2] and s[3] set to zeros. Now we check for a match in m[6..7], which will occur with probability 2^-64. This gives the attack a total success probability of 2^-96, violating the Level-1 claims. There may be much better attacks (by solving the bilinear forms in step 1 algebraically, rather than by brute force)

Note that the description of verification ("dme-open") in the document `Implementation of DME-3rnds-8vars-32bits-sign.pdf` only checks 128 bits of the w value (step 4); the attack would be more efficient in this case. The reference implementation further performs a consistency check of 8 bytes of g.
