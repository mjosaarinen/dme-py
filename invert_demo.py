#   invert_demo.py
#   2023-07-26  Markku-Juhani O. Saarinen <mjos@pqshield.com>. See LICENSE

#   Shows how to invert 128 bits of the one-way function quickly.

from aes_drbg import NIST_KAT_DRBG
from dme import DME
from random import randrange

def simple_pkey_map(self, pkey, sv):
    """Public-key mapping (simplified for sv[2] == sv[3] == 0.)"""
    (p, f) = pkey
    mv  =   [0] * 8

    #   words 0, 1
    t       =   [0] * 8
    t[0]    =   self.fq_pow2( sv[0], f[0] )
    t[1]    =   self.fq_pow2( sv[1], f[0] )
    t[4]    =   self.fq_pow2( sv[4], f[8] )
    t[5]    =   self.fq_pow2( sv[5], f[8] )
    t[6]    =   self.fq_pow2( sv[6], f[12] )
    t[7]    =   self.fq_pow2( sv[7], f[12] )

    c01     =   [0] * 65
    c01[4]  =   self.fq_mono([ t[6], t[4], t[0] ])
    c01[9]  =   self.fq_mono([ t[7], t[4], t[0] ])
    c01[14] =   self.fq_mono([ t[6], t[5], t[0] ])
    c01[19] =   self.fq_mono([ t[7], t[5], t[0] ])
    c01[24] =   self.fq_mono([ t[0] ])
    c01[27] =   self.fq_mono([ t[6], t[4], t[1] ])
    c01[30] =   self.fq_mono([ t[7], t[4], t[1] ])
    c01[33] =   self.fq_mono([ t[6], t[5], t[1] ])
    c01[36] =   self.fq_mono([ t[7], t[5], t[1] ])
    c01[39] =   self.fq_mono([ t[1] ])
    c01[44] =   self.fq_mono([ t[6], t[4] ])
    c01[49] =   self.fq_mono([ t[7], t[4] ])
    c01[54] =   self.fq_mono([ t[6], t[5] ])
    c01[59] =   self.fq_mono([ t[7], t[5] ])

    mv[0]   =   p[0][64]
    mv[1]   =   p[1][64]
    for i in range(64):
        mv[0]   ^=  self.fq_mul(c01[i], p[0][i])
        mv[1]   ^=  self.fq_mul(c01[i], p[1][i])

    #   words 2, 3
    t       =   [0] * 8
    t[4]    =   self.fq_pow2( sv[4], f[9] )
    t[5]    =   self.fq_pow2( sv[5], f[9] )
    t[6]    =   self.fq_pow2( sv[6], f[13] )
    t[7]    =   self.fq_pow2( sv[7], f[13] )

    c23     =   [0] * 25
    c23[20] =   self.fq_mono([ t[6], t[4] ])
    c23[21] =   self.fq_mono([ t[7], t[4] ])
    c23[22] =   self.fq_mono([ t[6], t[5] ])
    c23[23] =   self.fq_mono([ t[7], t[5] ])

    mv[2]   =   p[2][24]
    mv[3]   =   p[3][24]
    for i in range(20, 24):
        mv[2]   ^=  self.fq_mul(c23[i], p[2][i])
        mv[3]   ^=  self.fq_mul(c23[i], p[3][i])

    #   words 4, 5
    y       =   [0] * 8
    t[4]    =   self.fq_pow2( sv[4], f[10] )
    t[5]    =   self.fq_pow2( sv[5], f[10] )
    t[6]    =   self.fq_pow2( sv[6], f[14] )
    t[7]    =   self.fq_pow2( sv[7], f[14] )

    c45     =   [0] * 25
    c45[20] =   self.fq_mono([ t[6], t[4] ])
    c45[21] =   self.fq_mono([ t[7], t[4] ])
    c45[22] =   self.fq_mono([ t[6], t[5] ])
    c45[23] =   self.fq_mono([ t[7], t[5] ])

    mv[4]   =   p[4][24]
    mv[5]   =   p[5][24]
    for i in range(20, 24):
        mv[4]   ^=  self.fq_mul(c45[i], p[4][i])
        mv[5]   ^=  self.fq_mul(c45[i], p[5][i])

    #   words 6, 7
    t       =   [0] * 8
    t[4]    =   self.fq_pow2( sv[4], f[11] )
    t[5]    =   self.fq_pow2( sv[5], f[11] )
    t[6]    =   self.fq_pow2( sv[6], f[15] )
    t[7]    =   self.fq_pow2( sv[7], f[15] )
    tt      =   [ self.fq_mul( x, x ) for x in  y ]

    c67     =   [0] * 65
    c67[52] =   self.fq_mono([ t[6], tt[4] ])
    c67[53] =   self.fq_mono([ t[7], tt[4] ])
    c67[54] =   self.fq_mono([ t[6], t[5], t[4] ])
    c67[55] =   self.fq_mono([ t[7], t[5], t[4] ])
    c67[56] =   self.fq_mono([ t[4] ])
    c67[57] =   self.fq_mono([ t[6], tt[5] ])
    c67[58] =   self.fq_mono([ t[7], tt[5] ])
    c67[59] =   self.fq_mono([ t[5] ])
    c67[60] =   self.fq_mono([ t[6], t[4] ])
    c67[61] =   self.fq_mono([ t[7], t[4] ])
    c67[62] =   self.fq_mono([ t[6], t[5] ])
    c67[63] =   self.fq_mono([ t[7], t[5] ])

    mv[6]   =   p[6][64]
    mv[7]   =   p[7][64]
    for i in range(52, 64):
        mv[6]   ^=  self.fq_mul(c67[i], p[6][i])
        mv[7]   ^=  self.fq_mul(c67[i], p[7][i])

    return mv

def pmat(m):
    for i in range(len(m)):
        print(f'{i:3d}  {m[i]:032x}')

def gfmat_gauss(m):
    """Gaussian elimination in GF(2) -- in place."""
    d = len(m)

    for i in range(d):
        p = False
        for j in range(i, d):
            p = (m[j] >> i) & 1
            if p:
                if j != i:
                    m[i],m[j] = m[j],m[i]
                break
        if not p:
            return False
        for j in range(d):
            if j != i and (m[j] >> i) & 1:
                m[j] ^= m[i]
    return True

def gfmat_inv(m):
    """Invert a square matrix in GF(2) -- returns the matrix."""
    d = len(m)
    im = [ ((1 << (d + i)) | m[i]) for i in range(d) ]
    if not gfmat_gauss(im):
        return None
    for i in range(d):
        im[i] >>= d
    return im

def gfvec_mat(v, m):
    """Vector-matrix multiplication in GF(2)."""
    d = len(m)
    x = 0
    for i in range(d):
        if (v >> i) & 1:
            x ^= m[i]
    return x

def vec_to_num(vec):
    """Convert to an integer."""
    x = 0
    i = 0
    for t in vec:
        x ^= (t & 0xFFFFFFFF) << i
        i += 32
    return x

def vec_from_num(x, d):
    """Convert to number."""
    return [ ((x >> (32 * i)) & 0xFFFFFFFF) for i in range(d) ]

def solve_lin( dme, pkey, sv, src, dst, targ ):
    """Linear map of two words at src to targ at dst."""

    #   linear component
    tx  = vec_to_num(targ)
    sv0 = sv.copy()
    sv0[src : src + 2] = [0, 0]
    wg0 = simple_pkey_map(dme, pkey, sv0)
    w0  = vec_to_num(wg0[dst : dst + 2])

    #   create matrix
    mat = []
    for i in range(0,64):
        sv1 = sv0.copy()
        sv1[src + (i >> 5)] ^= 1 << (i & 0x1F)
        wg1 = simple_pkey_map(dme, pkey, sv1)
        w1  = vec_to_num(wg1[dst : dst + 2])
        mat += [ w0 ^ w1 ]

    inv = gfmat_inv(mat)
    if inv == None:
        return None

    r   = gfvec_mat(w0 ^ tx, inv)
    return vec_from_num(r, 2)

def str_vhex(v):
    """Hex string from 32-bit variables."""
    s = ''
    for x in v:
        s += f' {x:08x}'
    return s

if __name__ == '__main__':

    katnum = 5
    dme = DME()
    drbg = NIST_KAT_DRBG(bytes(range(48)))

    for count in range(katnum):

        print("=== count = ", count)

        seed = drbg.random_bytes(48)
        msg = drbg.random_bytes(33 * (count + 1))

        dme.set_random(NIST_KAT_DRBG(seed).random_bytes)
        (pk, sk) = dme.keygen()
        #print("pk =", pk.hex().upper())

        pkey = dme.pkey_parse(pk)

        #   start from a random vector
        sv = [ randrange(1 << 32) for _ in range(8) ]
        sv[2] = 0   #   zero signature words 2 and 3
        sv[3] = 0
        #   show that the simplified mapping is equivalent now
        m1 = dme.pkey_map(pkey, sv) # "official"
        m2 = simple_pkey_map(dme, pkey, sv) # "simplified"
        print("m1 =", str_vhex(m1))
        print("m2 =", str_vhex(m2))
        if m1 == m2:
            print("[OK] simplified mapping match.")
        else:
            print("[FAIL] simplified mapping mismatch.")

        #   set high signature as well (arbitrary)
        sv[6] = 0x01234567
        sv[7] = 0x89ABCDEF

        #   target for m[0:4] -- arbitrary
        targ = [ 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f ]

        #   force targ[2:4]
        r = solve_lin(dme, pkey, sv, 4, 2, targ[2:4])
        if r == None:
            print("[MISS] No inverse matrix for m[2:4].")
            continue
        sv[4:6] = r
        m3 = dme.pkey_map(pkey, sv)  # "official"
        print("m3 =", str_vhex(m3))
        if m3[2:4] == targ[2:4]:
            print("[OK] linear mapping to m[2:4]")
        else:
            print("[FAIL] linear algebra fail on m[2:4].")

        #   force targ[0:2]
        r = solve_lin(dme, pkey, sv, 0, 0, targ[0:2])
        if r == None:
            print("[MISS] No inverse matrix for m[0:2].")
            continue
        sv[0:2] = r
        print("sv =", str_vhex(sv))

        m4 = dme.pkey_map(pkey, sv) # "official"
        print("m4 =", str_vhex(m4))
        if m4[0:4] == targ:
            print("[OK] Half of function inverted!")
        else:
            print("[FAIL] linear algebra fail on m[0:4].")
        print()

