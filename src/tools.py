import ecdsa
import struct
import hashlib
import binascii
import mnemonic

Hash = lambda x: hashlib.sha256(hashlib.sha256(x).digest()).digest()
addrtype = 0

# secp256k1, http://www.oid-info.com/get/1.3.132.0.10
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
curve_secp256k1 = ecdsa.ellipticcurve.CurveFp( _p, _a, _b )
generator_secp256k1 = ecdsa.ellipticcurve.Point( curve_secp256k1, _Gx, _Gy, _r )
oid_secp256k1 = (1,3,132,0,10)
SECP256k1 = ecdsa.curves.Curve("SECP256k1", curve_secp256k1, generator_secp256k1, oid_secp256k1 )

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
    """ encode v, which is a string of bytes, to base58."""

    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0': nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result

def b58decode(v, length):
    """ decode v into a string of len bytes."""
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base**i)

    result = ''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]: nPad += 1
        else: break

    result = chr(0)*nPad + result
    if length is not None and len(result) != length:
        return None

    return result

def EncodeBase58Check(vchIn):
    # Used only for debug prints of private keys
    return b58encode(vchIn + Hash(vchIn)[0:4])

def SecretToASecret(secret):
    # Used only for debug prints of private keys
    vchIn = chr(addrtype+128) + secret
    return EncodeBase58Check(vchIn)

def hash_160(public_key):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
    return md.digest()

def hash_160_to_bc_address(h160):
    vh160 = chr(addrtype) + h160
    h = Hash(vh160)
    addr = vh160 + h[0:4]
    return b58encode(addr)

def bc_address_to_hash_160(addr):
    return b58decode(addr, 25)[1:21]

def public_key_to_bc_address(public_key):
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160)

def get_mnemonic(seed):
    return ' '.join(mnemonic.mn_encode(seed))

def get_seed(seed_words):
    return mnemonic.mn_decode(seed_words.split(' '))

def generate_seed(random):
    print "TODO: generate_seed: mix random and randrange together"  
    return "%032x" % ecdsa.util.randrange(pow(2, 128))
    
def var_int(i):
    if i<0xfd:
        return struct.pack('<B', i)
    elif i<=0xffff:
        return '\xfd' + struct.pack('<H', i)
    elif i<=0xffffffff:
        return '\xfe' + struct.pack('<Q', i)
    else:
        return '\xff' + struct.pack('<Q', i)

def get_secexp(seed):
    # Perform seed stretching    
    oldseed = seed
    for _ in range(100000):
        seed = hashlib.sha256(seed + oldseed).digest()
    return ecdsa.util.string_to_number(seed)
    
# https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
def raw_tx(inputs, outputs, for_sig):
    s  = '\x01\x00\x00\x00'                                  # version 
    s += var_int(len(inputs))                                # number of inputs
    for i in range(len(inputs)):
        inp = inputs[i] 
        
        s += inp.prev_hash[::-1]                              # prev hash
        s += struct.pack('<L', inp.prev_index)             # prev index

        if for_sig == i:
            script = inp.script_sig                        # scriptsig
        else:
            script=''
            
        s += var_int(len(script))                            # script length
        s += script
        s += "\xff\xff\xff\xff"                              # sequence
        
    s += var_int(len(outputs))                               # number of outputs
    for output in outputs:
        s += struct.pack('<Q', output.amount)                # amount 
        script = '\x76\xa9'                                  # op_dup, op_hash_160
        script += '\x14'                                     # push 0x14 bytes
        script += bc_address_to_hash_160(output.address)
        script += '\x88\xac'                                 # op_equalverify, op_checksig
        s += var_int(len(script))                            # script length
        s += script                                          # script
    s += '\x00\x00\x00\x00'                                  # lock time
    s += '\x01\x00\x00\x00'                                  # hash type
    return s

def sign_inputs(algo, seed, inputs, outputs):
    signatures = []
    for i in range(len(inputs)):
        addr_n = inputs[i].address_n
        print addr_n
        private_key = ecdsa.SigningKey.from_string(algo.get_private_key(seed, addr_n), curve=SECP256k1)

        tx = raw_tx(inputs, outputs, for_sig=i)
        sig = private_key.sign_digest(Hash(tx), sigencode=ecdsa.util.sigencode_der)
        #assert public_key.verify_digest(sig, Hash(tx.decode('hex')), sigdecode=ecdsa.util.sigdecode_der)
        #s_inputs.append((pubkey, sig))
        
        public_key = private_key.get_verifying_key()
        pubkey = public_key.to_string()
        
        signatures.append((pubkey, sig))
    return signatures

