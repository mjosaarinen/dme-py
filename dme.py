#   dme.py
#   2023-07-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>. See LICENSE

#   Implements PQC candidate DME-Sign with 8 variables and GF(2^32) (level I)

import os
from aes_drbg import NIST_KAT_DRBG
from Crypto.Hash import SHA3_256

class DME:

    def __init__(self, rbg=os.urandom):

        self.algname    = "dme-3rnds-8vars-32bits-sign"
        self.rbg        = rbg

        self.delta      = 57
        self.inv_delta  = 0x0204081020408101    #   Mod(2^57-1,2^64-1)^-1
        self.pk_sz      = 8 * (65 + 25 + 25 + 65) + 9
        self.sk_sz      = (4 * 4 * 2 * 2 * 4 + 8 * 4 * 3 + 6 + 6 + 5)
        self.sig_sz     = 32
        self.fq_deg     = 32
        self.fq_red     = 0x100000813           #   x^32 + x^11 + x^4 + x + 1

    #   public api

    def keygen(self):
        """Generate a public-private keypair."""
        skey = self.skey_gen()
        sk_b = self.skey_bytes(skey)
        pkey = self.pkey_gen(skey)
        pk_b = self.pkey_bytes(pkey)
        return (pk_b, sk_b)

    def sign(self, msg, sk_b):
        """Create a signed message."""
        #   parse secret
        skey =  self.skey_parse(sk_b)

        #   message + salt
        r = self.rbg(8)
        w = SHA3_256.new(msg + r).digest()

        #   upper half hash, encode salt
        g = list(SHA3_256.new(w[0:16]).digest())
        for i in range(8):
            g[i] ^= r[i]

        wg = w[0:16] + bytes(g[0:16])
        mv = [ self.fq_parse(wg[i:i+4]) for i in range(0,32,4) ]

        #   private key operation
        sv = self.skey_map(skey, mv)

        #   serialize signature
        sig = b''
        for i in range(8):
            sig += self.fq_bytes(sv[i])

        #   signed message
        sm = msg + sig

        return sm

    def open(self, sm, pk_b):
        """Check signature sm against pk. Return message or None on fail."""
        # parse public key
        if len(sm) < self.sig_sz:
            return None
        sig = sm[-self.sig_sz:]
        msg = sm[:-self.sig_sz]

        #   parse public key
        pkey = self.pkey_parse(pk_b)
        if pkey == None:
            return None

        #   parse signature
        sv = [ self.fq_parse(sig[i:i+4]) for i in range(0,32,4) ]

        #   public key operation
        mv = self.pkey_map(pkey, sv)

        #   serialize w and g
        wg = b''
        for i in range(8):
            wg += self.fq_bytes(mv[i])

        #   verification
        g2 = SHA3_256.new(wg[0:16]).digest()

        #   check 1: signature consistency (not in the spec?)
        if g2[8:16] != wg[24:32]:
            return None

        #   decode salt r, use the message
        r = bytes([ wg[16 + i] ^ g2[i] for i in range(8) ])
        w2 = SHA3_256.new(msg + r).digest()

        #   check 2: check against message
        if w2[0:16] != wg[0:16]:
            return None
        return msg

    def set_random(self, rbg):
        """Set the random number generator function."""
        self.rbg    = rbg

    #   higher level internal functions

    def skey_gen(self):
        """Generate a secret key."""
        l1, l1i  = [None] * 4, [None] * 4
        l2, l2i  = [None] * 4, [None] * 4
        l3, l3i  = [None] * 4, [None] * 4
        l4, l4i  = [None] * 4, [None] * 4
        for i in range(4):
            l1[i], l1i[i] = self.fq_2x2_rnd()
            l2[i], l2i[i] = self.fq_2x2_rnd()
            l3[i], l3i[i] = self.fq_2x2_rnd()
            l4[i], l4i[i] = self.fq_2x2_rnd()

        a2, a3, a4 = [None] * 4, [None] * 4, [None] * 4
        for i in range(4):
            a2[i] = self.fq2_rnd()
            a3[i] = self.fq2_rnd()
            a4[i] = self.fq2_rnd()

        a = list( self.rbg(6) )
        b = list( self.rbg(6) )
        c = list( self.rbg(8) )

        for i in range(6):
            a[i] &= 0x3F
            b[i] &= 0x3F
            c[i] &= 0x3F

        c[6] &= 0x3f
        c[1] = (a[0] + b[0] + c[0] - a[1] - b[2]) & 0x3f
        c[7] = (a[3] + b[4] + c[6] - a[4] - b[5]) & 0x3f
        c[4] = (c[2] + c[5] - c[3] + self.delta) & 0x3f

        return (l1, l1i, l2, l2i, l3, l3i, l4, l4i, a2, a3, a4, a, b, c)

    def pkey_gen(self, skey):
        """Derive a public key from secret key."""

        p01_4_red_idx = [
            0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 2,  3,  25, 26, 27,
            7,  8,  28, 29, 30, 12, 13, 31, 32, 33, 17, 18, 34, 35, 36,
            22, 23, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
            50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64  ]
        p23_4_red_idx = [
            0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24  ]
        p45_4_red_idx = [
            0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24  ]
        p67_4_red_idx = [
            0,  1,  2,  3,  4,  2,  3,  5,  6,  7,  8,  9,  10, 11, 12,
            13, 14, 15, 16, 17, 15, 16, 18, 19, 20, 21, 22, 23, 24, 25,
            26, 27, 28, 29, 30, 28, 29, 31, 32, 33, 34, 35, 36, 37, 38,
            39, 40, 41, 42, 43, 41, 42, 44, 45, 46, 47, 48, 49, 50, 51,
            52, 53, 54, 55, 56, 54, 55, 57, 58, 59, 60, 61, 62, 63, 64  ]

        (l1, l1i, l2, l2i, l3, l3i, l4, l4i, a2, a3, a4, a, b, c) = skey

        p01_1 = [ (1, 0), (0, 1) ]
        p23_1 = [ (1, 0), (0, 1) ]
        p45_1 = [ (1, 0), (0, 1) ]
        p67_1 = [ (1, 0), (0, 1) ]

        p01_1 = self.fq2_2x2_map_p(l1[0], p01_1[0:2])
        p23_1 = self.fq2_2x2_map_p(l1[1], p23_1[0:2])
        p45_1 = self.fq2_2x2_map_p(l1[2], p45_1[0:2])
        p67_1 = self.fq2_2x2_map_p(l1[3], p67_1[0:2])
        p01_2 = self.fq2_poly_pow2(p01_1[0:2], a[0])
        p23_2 = self.fq2_poly_prod(p01_1[0:2], a[1], p23_1[0:2], a[2])
        p45_2 = self.fq2_poly_pow2(p45_1[0:2], a[3])
        p67_2 = self.fq2_poly_prod(p45_1[0:2], a[4], p67_1[0:2], a[5])
        p01_2 = self.fq2_2x2_map_p(l2[0], p01_2[0:2]) + [ a2[0] ]
        p23_2 = self.fq2_2x2_map_p(l2[1], p23_2[0:4]) + [ a2[1] ]
        p45_2 = self.fq2_2x2_map_p(l2[2], p45_2[0:2]) + [ a2[2] ]
        p67_2 = self.fq2_2x2_map_p(l2[3], p67_2[0:4]) + [ a2[3] ]
        p01_3 = self.fq2_poly_prod(p01_2[0:3], b[0], p67_2[0:5], b[1])
        p23_3 = self.fq2_poly_pow2(p23_2[0:5], b[2])
        p45_3 = self.fq2_poly_prod(p23_2[0:5], b[3], p45_2[0:3], b[4])
        p67_3 = self.fq2_poly_pow2(p67_2[0:5], b[5])
        p01_3 = self.fq2_2x2_map_p(l3[0], p01_3[0:15])
        p23_3 = self.fq2_2x2_map_p(l3[1], p23_3[0:5])
        p45_3 = self.fq2_2x2_map_p(l3[2], p45_3[0:15])
        p67_3 = self.fq2_2x2_map_p(l3[3], p67_3[0:5])
        p01_3[14]   = self.fq2_add(p01_3[14], a3[0])
        p23_3[4]    = self.fq2_add(p23_3[4],  a3[1])
        p45_3[14]   = self.fq2_add(p45_3[14], a3[2])
        p67_3[4]    = self.fq2_add(p67_3[4],  a3[3])

        p01_4 = self.fq2_poly_prod(p01_3[0:15], c[0], p23_3[0:5], c[1])
        p23_4 = self.fq2_poly_prod(p23_3[0:5],  c[2], p67_3[0:5], c[3])
        p45_4 = self.fq2_poly_prod(p23_3[0:5],  c[4], p67_3[0:5], c[5])
        p67_4 = self.fq2_poly_prod(p45_3[0:15], c[6], p67_3[0:5], c[7])
        p01_4 = self.fq2_2x2_map_p(l4[0], p01_4[0:75])
        p23_4 = self.fq2_2x2_map_p(l4[1], p23_4[0:25])
        p45_4 = self.fq2_2x2_map_p(l4[2], p45_4[0:25])
        p67_4 = self.fq2_2x2_map_p(l4[3], p67_4[0:75])
        p01_4[74]   = self.fq2_add(p01_4[74], a4[0])
        p23_4[24]   = self.fq2_add(p23_4[24], a4[1])
        p45_4[24]   = self.fq2_add(p45_4[24], a4[2])
        p67_4[74]   = self.fq2_add(p67_4[74], a4[3])

        p   =   [   [0] * 65, [0] * 65, [0] * 25, [0] * 25,
                    [0] * 25, [0] * 25, [0] * 65, [0] * 65  ]
        for i in range(75):
            j       =   p01_4_red_idx[i]
            x0, x1  =   p01_4[i]
            p[0][j] ^=  x0
            p[1][j] ^=  x1
        for i in range(25):
            j       =   p23_4_red_idx[i]
            x0, x1  =   p23_4[i]
            p[2][j] ^=  x0
            p[3][j] ^=  x1
        for i in range(25):
            j       =   p45_4_red_idx[i]
            x0, x1  =   p45_4[i]
            p[4][j] ^=  x0
            p[5][j] ^=  x1
        for i in range(75):
            j       =   p67_4_red_idx[i]
            x0, x1  =   p67_4[i]
            p[6][j] ^=  x0
            p[7][j] ^=  x1

        f       = [0] * 16

        f[0]    = (a[0] + b[0] + c[0]) & 0x1f
        f[1]    = (a[1] + b[2] + c[2]) & 0x1f
        f[2]    = (a[1] + b[2] + c[4]) & 0x1f
        f[3]    = (a[1] + b[3] + c[6]) & 0x1f

        f[4]    = (a[2] + a[0] + b[0] - a[1] + c[0]) & 0x1f
        f[5]    = (a[2] + b[2] + c[2]) & 0x1f
        f[6]    = (a[2] + b[2] + c[4]) & 0x1f
        f[7]    = (a[2] + b[3] + c[6]) & 0x1f

        f[8]    = (a[4] + b[1] + c[0]) & 0x1f
        f[9]    = (a[4] + b[5] + c[3]) & 0x1f
        f[10]   = (a[4] + b[5] + c[5]) & 0x1f
        f[11]   = (a[3] + b[4] + c[6]) & 0x1f

        f[12]   = (a[5] + b[1] + c[0]) & 0x1f
        f[13]   = (a[5] + b[5] + c[3]) & 0x1f
        f[14]   = (a[5] + b[5] + c[5]) & 0x1f
        f[15]   = (a[5] + a[3] + b[4] - a[4] + c[6]) & 0x1f

        return (p, f)

    def pkey_map(self, pkey, sv):
        """Public-key mapping."""
        (p, f) = pkey
        y = [0] * 8

        y[0]    =   self.fq_pow2( sv[0], f[0] )
        y[1]    =   self.fq_pow2( sv[1], f[0] )
        y[2]    =   self.fq_pow2( sv[2], f[4] )
        y[3]    =   self.fq_pow2( sv[3], f[4] )
        y[4]    =   self.fq_pow2( sv[4], f[8] )
        y[5]    =   self.fq_pow2( sv[5], f[8] )
        y[6]    =   self.fq_pow2( sv[6], f[12] )
        y[7]    =   self.fq_pow2( sv[7], f[12] )
        z       =   [ self.fq_mul( x, x ) for x in  y ]

        c01     =   [0] * 65
        c01[0]  =   self.fq_mono([ y[2], z[0], y[6], y[4] ])
        c01[1]  =   self.fq_mono([ y[3], z[0], y[6], y[4] ])
        c01[2]  =   self.fq_mono([ y[2], y[1], y[6], y[4], y[0] ])
        c01[3]  =   self.fq_mono([ y[3], y[1], y[6], y[4], y[0] ])
        c01[4]  =   self.fq_mono([ y[6], y[4], y[0] ])
        c01[5]  =   self.fq_mono([ y[2], z[0], y[7], y[4] ])
        c01[6]  =   self.fq_mono([ y[3], z[0], y[7], y[4] ])
        c01[7]  =   self.fq_mono([ y[2], y[1], y[7], y[4], y[0] ])
        c01[8]  =   self.fq_mono([ y[3], y[1], y[7], y[4], y[0] ])
        c01[9]  =   self.fq_mono([ y[7], y[4], y[0] ])
        c01[10] =   self.fq_mono([ y[2], z[0], y[6], y[5] ])
        c01[11] =   self.fq_mono([ y[3], z[0], y[6], y[5] ])
        c01[12] =   self.fq_mono([ y[2], y[1], y[6], y[5], y[0] ])
        c01[13] =   self.fq_mono([ y[3], y[1], y[6], y[5], y[0] ])
        c01[14] =   self.fq_mono([ y[6], y[5], y[0] ])
        c01[15] =   self.fq_mono([ y[2], z[0], y[7], y[5] ])
        c01[16] =   self.fq_mono([ y[3], z[0], y[7], y[5] ])
        c01[17] =   self.fq_mono([ y[2], y[1], y[7], y[5], y[0] ])
        c01[18] =   self.fq_mono([ y[3], y[1], y[7], y[5], y[0] ])
        c01[19] =   self.fq_mono([ y[7], y[5], y[0] ])
        c01[20] =   self.fq_mono([ y[2], z[0] ])
        c01[21] =   self.fq_mono([ y[3], z[0] ])
        c01[22] =   self.fq_mono([ y[2], y[1], y[0] ])
        c01[23] =   self.fq_mono([ y[3], y[1], y[0] ])
        c01[24] =   self.fq_mono([ y[0] ])
        c01[25] =   self.fq_mono([ y[2], z[1], y[6], y[4] ])
        c01[26] =   self.fq_mono([ y[3], z[1], y[6], y[4] ])
        c01[27] =   self.fq_mono([ y[6], y[4], y[1] ])
        c01[28] =   self.fq_mono([ y[2], z[1], y[7], y[4] ])
        c01[29] =   self.fq_mono([ y[3], z[1], y[7], y[4] ])
        c01[30] =   self.fq_mono([ y[7], y[4], y[1] ])
        c01[31] =   self.fq_mono([ y[2], z[1], y[6], y[5] ])
        c01[32] =   self.fq_mono([ y[3], z[1], y[6], y[5] ])
        c01[33] =   self.fq_mono([ y[6], y[5], y[1] ])
        c01[34] =   self.fq_mono([ y[2], z[1], y[7], y[5] ])
        c01[35] =   self.fq_mono([ y[3], z[1], y[7], y[5] ])
        c01[36] =   self.fq_mono([ y[7], y[5], y[1] ])
        c01[37] =   self.fq_mono([ y[2], z[1] ])
        c01[38] =   self.fq_mono([ y[3], z[1] ])
        c01[39] =   self.fq_mono([ y[1] ])
        c01[40] =   self.fq_mono([ y[2], y[0], y[6], y[4] ])
        c01[41] =   self.fq_mono([ y[3], y[0], y[6], y[4] ])
        c01[42] =   self.fq_mono([ y[2], y[1], y[6], y[4] ])
        c01[43] =   self.fq_mono([ y[3], y[1], y[6], y[4] ])
        c01[44] =   self.fq_mono([ y[6], y[4] ])
        c01[45] =   self.fq_mono([ y[2], y[0], y[7], y[4] ])
        c01[46] =   self.fq_mono([ y[3], y[0], y[7], y[4] ])
        c01[47] =   self.fq_mono([ y[2], y[1], y[7], y[4] ])
        c01[48] =   self.fq_mono([ y[3], y[1], y[7], y[4] ])
        c01[49] =   self.fq_mono([ y[7], y[4] ])
        c01[50] =   self.fq_mono([ y[2], y[0], y[6], y[5] ])
        c01[51] =   self.fq_mono([ y[3], y[0], y[6], y[5] ])
        c01[52] =   self.fq_mono([ y[2], y[1], y[6], y[5] ])
        c01[53] =   self.fq_mono([ y[3], y[1], y[6], y[5] ])
        c01[54] =   self.fq_mono([ y[6], y[5] ])
        c01[55] =   self.fq_mono([ y[2], y[0], y[7], y[5] ])
        c01[56] =   self.fq_mono([ y[3], y[0], y[7], y[5] ])
        c01[57] =   self.fq_mono([ y[2], y[1], y[7], y[5] ])
        c01[58] =   self.fq_mono([ y[3], y[1], y[7], y[5] ])
        c01[59] =   self.fq_mono([ y[7], y[5] ])
        c01[60] =   self.fq_mono([ y[2], y[0] ])
        c01[61] =   self.fq_mono([ y[3], y[0] ])
        c01[62] =   self.fq_mono([ y[2], y[1] ])
        c01[63] =   self.fq_mono([ y[3], y[1] ])
        c01[64] =   1

        y[0]    =   self.fq_pow2( sv[0], f[1] )
        y[1]    =   self.fq_pow2( sv[1], f[1] )
        y[2]    =   self.fq_pow2( sv[2], f[5] )
        y[3]    =   self.fq_pow2( sv[3], f[5] )
        y[4]    =   self.fq_pow2( sv[4], f[9] )
        y[5]    =   self.fq_pow2( sv[5], f[9] )
        y[6]    =   self.fq_pow2( sv[6], f[13] )
        y[7]    =   self.fq_pow2( sv[7], f[13] )
        z       =   [ self.fq_mul( x, x ) for x in  y ]

        c23     =   [0] * 25
        c23[0]  =   self.fq_mono([ y[6], y[4], y[2], y[0] ])
        c23[1]  =   self.fq_mono([ y[7], y[4], y[2], y[0] ])
        c23[2]  =   self.fq_mono([ y[6], y[5], y[2], y[0] ])
        c23[3]  =   self.fq_mono([ y[7], y[5], y[2], y[0] ])
        c23[4]  =   self.fq_mono([ y[2], y[0] ])
        c23[5]  =   self.fq_mono([ y[6], y[4], y[3], y[0] ])
        c23[6]  =   self.fq_mono([ y[7], y[4], y[3], y[0] ])
        c23[7]  =   self.fq_mono([ y[6], y[5], y[3], y[0] ])
        c23[8]  =   self.fq_mono([ y[7], y[5], y[3], y[0] ])
        c23[9]  =   self.fq_mono([ y[3], y[0] ])
        c23[10] =   self.fq_mono([ y[6], y[4], y[2], y[1] ])
        c23[11] =   self.fq_mono([ y[7], y[4], y[2], y[1] ])
        c23[12] =   self.fq_mono([ y[6], y[5], y[2], y[1] ])
        c23[13] =   self.fq_mono([ y[7], y[5], y[2], y[1] ])
        c23[14] =   self.fq_mono([ y[2], y[1] ])
        c23[15] =   self.fq_mono([ y[6], y[4], y[3], y[1] ])
        c23[16] =   self.fq_mono([ y[7], y[4], y[3], y[1] ])
        c23[17] =   self.fq_mono([ y[6], y[5], y[3], y[1] ])
        c23[18] =   self.fq_mono([ y[7], y[5], y[3], y[1] ])
        c23[19] =   self.fq_mono([ y[3], y[1] ])
        c23[20] =   self.fq_mono([ y[6], y[4] ])
        c23[21] =   self.fq_mono([ y[7], y[4] ])
        c23[22] =   self.fq_mono([ y[6], y[5] ])
        c23[23] =   self.fq_mono([ y[7], y[5] ])
        c23[24] =   1

        y[0]    =   self.fq_pow2( sv[0], f[2] )
        y[1]    =   self.fq_pow2( sv[1], f[2] )
        y[2]    =   self.fq_pow2( sv[2], f[6] )
        y[3]    =   self.fq_pow2( sv[3], f[6] )
        y[4]    =   self.fq_pow2( sv[4], f[10] )
        y[5]    =   self.fq_pow2( sv[5], f[10] )
        y[6]    =   self.fq_pow2( sv[6], f[14] )
        y[7]    =   self.fq_pow2( sv[7], f[14] )
        z       =   [ self.fq_mul( x, x ) for x in  y ]

        c45     =   [0] * 25
        c45[0]  =   self.fq_mono([ y[6], y[4], y[2], y[0] ])
        c45[1]  =   self.fq_mono([ y[7], y[4], y[2], y[0] ])
        c45[2]  =   self.fq_mono([ y[6], y[5], y[2], y[0] ])
        c45[3]  =   self.fq_mono([ y[7], y[5], y[2], y[0] ])
        c45[4]  =   self.fq_mono([ y[2], y[0] ])
        c45[5]  =   self.fq_mono([ y[6], y[4], y[3], y[0] ])
        c45[6]  =   self.fq_mono([ y[7], y[4], y[3], y[0] ])
        c45[7]  =   self.fq_mono([ y[6], y[5], y[3], y[0] ])
        c45[8]  =   self.fq_mono([ y[7], y[5], y[3], y[0] ])
        c45[9]  =   self.fq_mono([ y[3], y[0] ])
        c45[10] =   self.fq_mono([ y[6], y[4], y[2], y[1] ])
        c45[11] =   self.fq_mono([ y[7], y[4], y[2], y[1] ])
        c45[12] =   self.fq_mono([ y[6], y[5], y[2], y[1] ])
        c45[13] =   self.fq_mono([ y[7], y[5], y[2], y[1] ])
        c45[14] =   self.fq_mono([ y[2], y[1] ])
        c45[15] =   self.fq_mono([ y[6], y[4], y[3], y[1] ])
        c45[16] =   self.fq_mono([ y[7], y[4], y[3], y[1] ])
        c45[17] =   self.fq_mono([ y[6], y[5], y[3], y[1] ])
        c45[18] =   self.fq_mono([ y[7], y[5], y[3], y[1] ])
        c45[19] =   self.fq_mono([ y[3], y[1] ])
        c45[20] =   self.fq_mono([ y[6], y[4] ])
        c45[21] =   self.fq_mono([ y[7], y[4] ])
        c45[22] =   self.fq_mono([ y[6], y[5] ])
        c45[23] =   self.fq_mono([ y[7], y[5] ])
        c45[24] =   1

        y[0]    =   self.fq_pow2( sv[0], f[3] )
        y[1]    =   self.fq_pow2( sv[1], f[3] )
        y[2]    =   self.fq_pow2( sv[2], f[7] )
        y[3]    =   self.fq_pow2( sv[3], f[7] )
        y[4]    =   self.fq_pow2( sv[4], f[11] )
        y[5]    =   self.fq_pow2( sv[5], f[11] )
        y[6]    =   self.fq_pow2( sv[6], f[15] )
        y[7]    =   self.fq_pow2( sv[7], f[15] )
        z       =   [ self.fq_mul( x, x ) for x in  y ]

        c67     =   [0] * 65
        c67[0]  =   self.fq_mono([ y[6], z[4], y[2], y[0] ])
        c67[1]  =   self.fq_mono([ y[7], z[4], y[2], y[0] ])
        c67[2]  =   self.fq_mono([ y[6], y[5], y[4], y[2], y[0] ])
        c67[3]  =   self.fq_mono([ y[7], y[5], y[4], y[2], y[0] ])
        c67[4]  =   self.fq_mono([ y[4], y[2], y[0] ])
        c67[5]  =   self.fq_mono([ y[6], z[5], y[2], y[0] ])
        c67[6]  =   self.fq_mono([ y[7], z[5], y[2], y[0] ])
        c67[7]  =   self.fq_mono([ y[5], y[2], y[0] ])
        c67[8]  =   self.fq_mono([ y[6], y[4], y[2], y[0] ])
        c67[9]  =   self.fq_mono([ y[7], y[4], y[2], y[0] ])
        c67[10] =   self.fq_mono([ y[6], y[5], y[2], y[0] ])
        c67[11] =   self.fq_mono([ y[7], y[5], y[2], y[0] ])
        c67[12] =   self.fq_mono([ y[2], y[0] ])
        c67[13] =   self.fq_mono([ y[6], z[4], y[3], y[0] ])
        c67[14] =   self.fq_mono([ y[7], z[4], y[3], y[0] ])
        c67[15] =   self.fq_mono([ y[6], y[5], y[4], y[3], y[0] ])
        c67[16] =   self.fq_mono([ y[7], y[5], y[4], y[3], y[0] ])
        c67[17] =   self.fq_mono([ y[4], y[3], y[0] ])
        c67[18] =   self.fq_mono([ y[6], z[5], y[3], y[0] ])
        c67[19] =   self.fq_mono([ y[7], z[5], y[3], y[0] ])
        c67[20] =   self.fq_mono([ y[5], y[3], y[0] ])
        c67[21] =   self.fq_mono([ y[6], y[4], y[3], y[0] ])
        c67[22] =   self.fq_mono([ y[7], y[4], y[3], y[0] ])
        c67[23] =   self.fq_mono([ y[6], y[5], y[3], y[0] ])
        c67[24] =   self.fq_mono([ y[7], y[5], y[3], y[0] ])
        c67[25] =   self.fq_mono([ y[3], y[0] ])
        c67[26] =   self.fq_mono([ y[6], z[4], y[2], y[1] ])
        c67[27] =   self.fq_mono([ y[7], z[4], y[2], y[1] ])
        c67[28] =   self.fq_mono([ y[6], y[5], y[4], y[2], y[1] ])
        c67[29] =   self.fq_mono([ y[7], y[5], y[4], y[2], y[1] ])
        c67[30] =   self.fq_mono([ y[4], y[2], y[1] ])
        c67[31] =   self.fq_mono([ y[6], z[5], y[2], y[1] ])
        c67[32] =   self.fq_mono([ y[7], z[5], y[2], y[1] ])
        c67[33] =   self.fq_mono([ y[5], y[2], y[1] ])
        c67[34] =   self.fq_mono([ y[6], y[4], y[2], y[1] ])
        c67[35] =   self.fq_mono([ y[7], y[4], y[2], y[1] ])
        c67[36] =   self.fq_mono([ y[6], y[5], y[2], y[1] ])
        c67[37] =   self.fq_mono([ y[7], y[5], y[2], y[1] ])
        c67[38] =   self.fq_mono([ y[2], y[1] ])
        c67[39] =   self.fq_mono([ y[6], z[4], y[3], y[1] ])
        c67[40] =   self.fq_mono([ y[7], z[4], y[3], y[1] ])
        c67[41] =   self.fq_mono([ y[6], y[5], y[4], y[3], y[1] ])
        c67[42] =   self.fq_mono([ y[7], y[5], y[4], y[3], y[1] ])
        c67[43] =   self.fq_mono([ y[4], y[3], y[1] ])
        c67[44] =   self.fq_mono([ y[6], z[5], y[3], y[1] ])
        c67[45] =   self.fq_mono([ y[7], z[5], y[3], y[1] ])
        c67[46] =   self.fq_mono([ y[5], y[3], y[1] ])
        c67[47] =   self.fq_mono([ y[6], y[4], y[3], y[1] ])
        c67[48] =   self.fq_mono([ y[7], y[4], y[3], y[1] ])
        c67[49] =   self.fq_mono([ y[6], y[5], y[3], y[1] ])
        c67[50] =   self.fq_mono([ y[7], y[5], y[3], y[1] ])
        c67[51] =   self.fq_mono([ y[3], y[1] ])
        c67[52] =   self.fq_mono([ y[6], z[4] ])
        c67[53] =   self.fq_mono([ y[7], z[4] ])
        c67[54] =   self.fq_mono([ y[6], y[5], y[4] ])
        c67[55] =   self.fq_mono([ y[7], y[5], y[4] ])
        c67[56] =   self.fq_mono([ y[4] ])
        c67[57] =   self.fq_mono([ y[6], z[5] ])
        c67[58] =   self.fq_mono([ y[7], z[5] ])
        c67[59] =   self.fq_mono([ y[5] ])
        c67[60] =   self.fq_mono([ y[6], y[4] ])
        c67[61] =   self.fq_mono([ y[7], y[4] ])
        c67[62] =   self.fq_mono([ y[6], y[5] ])
        c67[63] =   self.fq_mono([ y[7], y[5] ])
        c67[64] =   1

        #   polynomial evaluation
        mv  =   [0] * 8
        for i in range(65):
            mv[0]   ^=  self.fq_mul(c01[i], p[0][i])
            mv[1]   ^=  self.fq_mul(c01[i], p[1][i])
        for i in range(25):
            mv[2]   ^=  self.fq_mul(c23[i], p[2][i])
            mv[3]   ^=  self.fq_mul(c23[i], p[3][i])
        for i in range(25):
            mv[4]   ^=  self.fq_mul(c45[i], p[4][i])
            mv[5]   ^=  self.fq_mul(c45[i], p[5][i])
        for i in range(65):
            mv[6]   ^=  self.fq_mul(c67[i], p[6][i])
            mv[7]   ^=  self.fq_mul(c67[i], p[7][i])

        return mv

    def skey_map(self, skey, mv):
        """Secret-key mapping."""
        (l1, l1i, l2, l2i, l3, l3i, l4, l4i, a2, a3, a4, a, b, c) = skey

        x = [ self.fq2_add( (mv[2*i], mv[2*i+1]), a4[i] ) for i in range(4) ]
        y = [ self.fq_2x2_map( l4i[i], x[i] ) for i in range(4) ]

        inv1 = self.fq2_inv(y[1])
        inv2 = self.fq2_inv(y[2])
        tmp1 = self.fq2_pow2(inv2, (c[1] - c[0] - c[4] + self.delta) & 0x3f)
        tmp2 = self.fq2_pow2(y[1], (c[1] - c[0] - c[2]) & 0x3f)
        tmp1 = self.fq2_mul(tmp1, tmp2)
        tmp1 = self.fq2_exp(tmp1, self.inv_delta)
        tmp2 = self.fq2_pow2(y[0], -c[0] & 0x3f)
        x[0] = self.fq2_mul(tmp1, tmp2)
        tmp1 = self.fq2_pow2(inv1, -c[2] & 0x3f)
        tmp2 = self.fq2_pow2(y[2], (c[3] - c[2] - c[5]) & 0x3f)
        tmp1 = self.fq2_mul(tmp1, tmp2)
        x[1] = self.fq2_exp(tmp1, self.inv_delta)
        tmp1 = self.fq2_pow2(y[2], (c[7] - c[6] - c[5]) & 0x3f)
        tmp2 = self.fq2_pow2(inv1, (c[7] - c[6] - c[3] + self.delta) & 0x3f)
        tmp1 = self.fq2_mul(tmp1, tmp2)
        tmp1 = self.fq2_exp(tmp1, self.inv_delta)
        tmp2 = self.fq2_pow2(y[3], -c[6] & 0x3f)
        x[2] = self.fq2_mul(tmp1, tmp2)
        tmp1 = self.fq2_pow2(y[1], (self.delta - c[3]) & 0x3f)
        tmp2 = self.fq2_pow2(inv2, -c[5] & 0x3f)
        tmp1 = self.fq2_mul(tmp1, tmp2)
        x[3] = self.fq2_exp(tmp1, self.inv_delta)

        x = [ self.fq2_add( x[i], a3[i] ) for i in range(4) ]
        y = [ self.fq_2x2_map( l3i[i], x[i] ) for i in range(4) ]

        inv1 = self.fq2_inv(y[3])
        tmp1 = self.fq2_pow2(y[0], -b[0] & 0x3f)
        tmp2 = self.fq2_pow2(inv1, (b[1] - b[0] - b[5]) & 0x3f)
        x[0] = self.fq2_mul(tmp1, tmp2)
        x[1] = self.fq2_pow2(y[1], -b[2] & 0x3f)
        inv2 = self.fq2_inv(y[1])
        tmp1 = self.fq2_pow2(y[2], -b[4] & 0x3f)
        tmp2 = self.fq2_pow2(inv2, (b[3] - b[4] - b[2]) & 0x3f)
        x[2] = self.fq2_mul(tmp1, tmp2)
        x[3] = self.fq2_pow2(y[3], -b[5] & 0x3f)

        x = [ self.fq2_add( x[i], a2[i] ) for i in range(4) ]
        y = [ self.fq_2x2_map( l2i[i], x[i] ) for i in range(4) ]

        inv1 = self.fq2_inv(y[0])
        x[0] = self.fq2_pow2(y[0], -a[0] & 0x3f)
        tmp1 = self.fq2_pow2(inv1, (a[1] - a[0] - a[2]) & 0x3f)
        tmp2 = self.fq2_pow2(y[1], -a[2] & 0x3f)
        x[1] = self.fq2_mul(tmp1, tmp2)
        inv2 = self.fq2_inv(y[2])
        x[2] = self.fq2_pow2(y[2], -a[3] & 0x3f)
        tmp1 = self.fq2_pow2(inv2, (a[4] - a[3] - a[5]) & 0x3f)
        tmp2 = self.fq2_pow2(y[3], -a[5] & 0x3f)
        x[3] = self.fq2_mul( tmp1, tmp2)

        y = [ self.fq_2x2_map( l1i[i], x[i] ) for i in range(4) ]

        sv  =   [   y[0][0],  y[0][1], y[1][0],  y[1][1],
                    y[2][0],  y[2][1], y[3][0],  y[3][1]    ]
        return  sv

    #   key serialization / deserialization

    def pkey_parse(self, s):
        """Parse a public key from bytes."""
        if len(s) != self.pk_sz:
            return None

        p = [ [], [], [], [], [], [], [], [] ]

        for i in range(65):
            p[0] += [ self.fq_parse(s[0:4]) ]
            p[1] += [ self.fq_parse(s[4:8]) ]
            s = s[8:]
        for i in range(25):
            p[2] += [ self.fq_parse(s[0:4]) ]
            p[3] += [ self.fq_parse(s[4:8]) ]
            s = s[8:]
        for i in range(25):
            p[4] += [ self.fq_parse(s[0:4]) ]
            p[5] += [ self.fq_parse(s[4:8]) ]
            s = s[8:]
        for i in range(65):
            p[6] += [ self.fq_parse(s[0:4]) ]
            p[7] += [ self.fq_parse(s[4:8]) ]
            s = s[8:]

        f = [0] * 16
        f[0]    = s[0]
        f[1]    = s[1]
        f[3]    = s[2]
        f[5]    = s[3]
        f[8]    = s[4]
        f[9]    = s[5]
        f[10]   = s[6]
        f[11]   = s[7]
        f[12]   = s[8]
        for t in f:
            if t >= 32:
                return None
        f[2]    = (f[1]  + f[10] - f[9] + self.delta) & 0x1f
        f[4]    = (f[0]  + f[5]  - f[1]) & 0x1f
        f[6]    = (f[5]  + f[2]  - f[1]) & 0x1f
        f[7]    = (f[5]  + f[3]  - f[1]) & 0x1f
        f[13]   = (f[12] + f[9]  - f[8]) & 0x1f
        f[14]   = (f[12] + f[10] - f[8]) & 0x1f
        f[15]   = (f[11] + f[12] - f[8]) & 0x1f

        return (p, f)

    def pkey_bytes(self, pkey):
        """Serialize a public key."""
        (p, f) = pkey

        s = b''
        for i in range(65):
            s += self.fq_bytes(p[0][i]) + self.fq_bytes(p[1][i])
        for i in range(25):
            s += self.fq_bytes(p[2][i]) + self.fq_bytes(p[3][i])
        for i in range(25):
            s += self.fq_bytes(p[4][i]) + self.fq_bytes(p[5][i])
        for i in range(65):
            s += self.fq_bytes(p[6][i]) + self.fq_bytes(p[7][i])

        s += bytes([f[0], f[1], f[3], f[5], f[8], f[9], f[10], f[11], f[12]])

        return s

    def skey_parse(self, s):
        """Parse secret key from bytes."""
        if len(s) != self.sk_sz:
            return None

        l1, l1i  = [None] * 4, [None] * 4
        l2, l2i  = [None] * 4, [None] * 4
        l3, l3i  = [None] * 4, [None] * 4
        l4, l4i  = [None] * 4, [None] * 4
        for i in range(4):
            l1i[i]  = self.fq_2x2_parse(s[0:16])
            l1[i]   = self.fq_2x2_inv(l1i[i])
            l2i[i]  = self.fq_2x2_parse(s[16:32])
            l2[i]   = self.fq_2x2_inv(l2i[i])
            l3i[i]  = self.fq_2x2_parse(s[32:48])
            l3[i]   = self.fq_2x2_inv(l3i[i])
            l4i[i]  = self.fq_2x2_parse(s[48:64])
            l4[i]   = self.fq_2x2_inv(l4i[i])
            s = s[64:]

        a2, a3, a4 = [None] * 4, [None] * 4, [None] * 4
        for i in range(4):
            a2[i] = self.fq2_parse(s[0:8])
            a3[i] = self.fq2_parse(s[8:16])
            a4[i] = self.fq2_parse(s[16:24])
            s = s[24:]

        a = list( s[0:6] )
        s = s[6:]
        b = list( s[0:6] )
        s = s[6:]
        c = [0] * 8
        c[0], c[2], c[3], c[5], c[6] = s[0], s[1], s[2], s[3], s[4]

        c[1] = (a[0] + b[0] + c[0] - a[1] - b[2]) & 0x3f
        c[7] = (a[3] + b[4] + c[6] - a[4] - b[5]) & 0x3f
        c[4] = (c[2] + c[5] - c[3] + self.delta) & 0x3f

        return (l1, l1i, l2, l2i, l3, l3i, l4, l4i, a2, a3, a4, a, b, c)

    def skey_bytes(self, skey):
        """Serialize a secret key to bytes."""
        (l1, l1i, l2, l2i, l3, l3i, l4, l4i, a2, a3, a4, a, b, c) = skey
        s = b''
        for i in range(4):
            s += self.fq_2x2_bytes( l1i[i] )
            s += self.fq_2x2_bytes( l2i[i] )
            s += self.fq_2x2_bytes( l3i[i] )
            s += self.fq_2x2_bytes( l4i[i] )
        for i in range(4):
            s += self.fq2_bytes( a2[i] )
            s += self.fq2_bytes( a3[i] )
            s += self.fq2_bytes( a4[i] )
        s += bytes( a )
        s += bytes( b )
        s += bytes([ c[0], c[2], c[3], c[5], c[6] ])
        return s


    #   arithmetic

    def fq_parse(self, s):
        """Parse a field element from bytes."""
        return s[0] + (s[1] << 8) + (s[2] << 16) + (s[3] << 24)

    def fq_bytes(self, x):
        """Serialize a field element to bytes."""
        return bytes([  x & 0xFF,           (x >> 8) & 0xFF,
                        (x >> 16) & 0xFF,   (x >> 24) & 0xFF ])

    def fq_rnd(self):
        """Generate a random field element."""
        return self.fq_parse(self.rbg(4))

    def fq_mul(self, x, y):
        """Finite field multiplication x*y."""
        if y & 1:
            r = x
        else:
            r = 0
        while y > 1:
            x <<= 1
            if (x >> self.fq_deg) & 1:
                x ^= self.fq_red
            y >>= 1
            if y & 1:
                r ^= x
        return r

    def fq_exp(self, x, e):
        """Exponentiation x**e in Fq."""
        if e & 1:
            r = x
        else:
            r = 1
        while e > 1:
            e >>= 1
            x = self.fq_mul(x, x)
            if e & 1:
                r = self.fq_mul(r, x)
        return r

    def fq_inv(self, x):
        """Invert a Fq element."""
        return self.fq_exp(x, (1 << self.fq_deg) - 2)

    def fq2_pow2(self, a, k):
        """Compute a**(2**k) in Fq2."""
        for _ in range(k):
            a = self.fq2_mul(a, a)
        return a

    def fq_mono(self, v):
        """Create monomial product of v."""
        if len(v) == 0:
            return 1
        x = v[0]
        for y in v[1:]:
            x = self.fq_mul(x,  y)
        return x

    def fq2_add(self, x, y):
        """Fq2 addition: x+y."""
        return (x[0] ^ y[0], x[1] ^ y[1])

    def fq2_parse(self, s):
        """Parse a Fq2 element."""
        return ( self.fq_parse(s[0:4]), self.fq_parse(s[4:8]) )

    def fq2_bytes(self, xy):
        """Convert a Fq2 to bytes."""
        (x, y) = xy
        return self.fq_bytes(x) + self.fq_bytes(y)

    def fq2_rnd(self):
        """Generate a random Fq2 element."""
        return ( self.fq_rnd(), self.fq_rnd() )

    def fq2_mul(self, x, y):
        """Fq2 multiplication: x*y."""
        d = (   self.fq_mul(x[0], y[0]),
                self.fq_mul(x[0], y[1]) ^ self.fq_mul(x[1], y[0]) )
        t = self.fq_mul(x[1], y[1])
        return ( d[0] ^ self.fq_mul(1, t), d[1] ^ self.fq_mul(2, t) )

    def fq_pow2(self, a, k):
        """Compute a**(2**k) in the finite field."""
        for _ in range(k):
            a = self.fq_mul(a, a)
        return a

    def fq2_exp(self, x, e):
        """Exponentiation x**e in Fq2."""
        if e & 1:
            r = x
        else:
            r = ( 1, 0 )
        while e > 1:
            e >>= 1
            x = self.fq2_mul(x, x)
            if e & 1:
                r = self.fq2_mul(r, x)
        return r

    def fq2_inv(self, x):
        """Invert an element in Fq2."""
        return self.fq2_exp(x, (1 << (2*self.fq_deg)) - 2)

    def fq2_poly_pow2(self, q, k):
        """Raise every element to 2**k."""
        return [ self.fq2_pow2(a, k) for a in q ]

    def fq2_poly_prod(self, q1, a1, q2, a2):
        r = []
        for x1 in q1:
            t1 = self.fq2_pow2(x1, a1)
            for x2 in q2:
                t2 = self.fq2_pow2(x2, a2)
                r += [ self.fq2_mul( t1, t2 ) ]
        return r

    def fq_2x2_parse(self, s):
        """Parse a 2x2 matrix."""
        return [    self.fq_parse(s[0:4]),  self.fq_parse(s[4:8]),
                    self.fq_parse(s[8:12]), self.fq_parse(s[12:16]) ]

    def fq_2x2_bytes(self, m):
        """Serialize a 2x2 matrix."""
        return (self.fq_bytes(m[0]) + self.fq_bytes(m[1]) +
                self.fq_bytes(m[2]) + self.fq_bytes(m[3]) )

    def fq_2x2_inv(self, m):
        """Invert a 2x2 matrix."""
        d = self.fq_mul(m[0], m[3]) ^ self.fq_mul(m[1], m[2])
        if d == 0:
            return None
        d = self.fq_inv(d)
        return [    self.fq_mul(d, m[3]), self.fq_mul(d, m[1]),
                    self.fq_mul(d, m[2]), self.fq_mul(d, m[0]) ]

    def fq_2x2_rnd(self):
        """Find a random invertible 2x2 matrix and its inverse."""
        inv = None
        while inv == None:
            mat = [ self.fq_rnd() for _ in range(4) ]
            inv = self.fq_2x2_inv(mat)
        return mat, inv

    def fq_2x2_map(self, m, y):
        """Multiply 2x2 matrix with vector."""
        return (    self.fq_mul(m[0], y[0]) ^ self.fq_mul(m[1], y[1]),
                    self.fq_mul(m[2], y[0]) ^ self.fq_mul(m[3], y[1]) )

    def fq2_2x2_map_p(self, m, q):
        return [ self.fq_2x2_map(m, x) for x in q ]


#   NIST KAT tester

def test_rsp(iut, katnum=100):
    """Print NIST-styte KAT response files."""
    drbg    = NIST_KAT_DRBG(bytes(range(48)))
    print(f"# {iut.algname}\n")
    for count in range(katnum):
        print("count =", count)
        seed = drbg.random_bytes(48)
        iut.set_random(NIST_KAT_DRBG(seed).random_bytes)
        print("seed =", seed.hex().upper())
        mlen = 33 * (count + 1)
        print("mlen =", mlen)
        msg = drbg.random_bytes(mlen)
        print("msg =", msg.hex().upper())
        (pk, sk) = iut.keygen()
        print("pk =", pk.hex().upper())
        print("sk =", sk.hex().upper())
        sm = iut.sign(msg, sk)
        print("smlen =", len(sm))
        print("sm =", sm.hex().upper())
        print()
        m2 = iut.open(sm, pk)
        if m2 == None or m2 != msg:
            print("(verify error)")

if __name__ == '__main__':
    test_rsp(DME())

