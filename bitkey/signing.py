import struct
import ecdsa

import bitkey_pb2 as proto
import tools

def raw_tx_header(inputs_count):
    s = ''
    s += '\x01\x00\x00\x00'                                  # version 
    s += tools.var_int(inputs_count)                               # number of inputs
    return s

def raw_tx_input(inp, script_sig):
    s = ''
    s += inp.prev_hash[::-1]                              # prev hash
    s += struct.pack('<L', inp.prev_index)             # prev index
    if script_sig != '':
        s += tools.var_int(len(script_sig))              # script length
        s += script_sig                                  # script sig
    s += "\xff\xff\xff\xff"                              # sequence
    return s

def raw_tx_middle(outputs_count):
    s = ''
    s += tools.var_int(outputs_count)                               # number of outputs
    return s

def raw_tx_output(out):
    s = ''
    s += struct.pack('<Q', out.amount)                # amount 
    
    if out.script_type == proto.PAYTOADDRESS:
        script = '\x76\xa9'                                  # op_dup, op_hash_160
        script += '\x14'                                     # push 0x14 bytes
        script += tools.bc_address_to_hash_160(out.address)
        script += '\x88\xac'                                 # op_equalverify, op_checksig
        
    elif out.script_type == proto.PAYTOSCRIPTHASH:
        raise Exception("P2SH not implemented yet!")
    
    else:
        raise Exception("Unknown script type!")
    
    s += tools.var_int(len(script))                            # script length
    s += script                                          # script
    return s

def raw_tx_footer(for_sign):
    s = ''
    s += '\x00\x00\x00\x00'                                  # lock time
    if for_sign:
        s += '\x01\x00\x00\x00'                             # hash type
    return s

'''
# https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
def raw_tx(inputs, outputs, for_sig):
    s = ''
    s += raw_tx_header(len(inputs))
    
    for i in range(len(inputs)):
        inp = inputs[i] 
    
        if for_sig == i:
            script_sig = inp.script_sig
        else:
            script_sig = ''

        s += raw_tx_input(inp, script_sig)
        
    s += raw_tx_middle(len(outputs))
    
    for output in outputs:
        s += raw_tx_output(output)

    s += raw_tx_footer()
    return s
'''

def sign_input(algo, secexp, addr_n, tx_hash):
    pk = algo.get_private_key(secexp, addr_n)
    private_key = ecdsa.SigningKey.from_string(pk, curve=tools.SECP256k1)
    sig = private_key.sign_digest(tx_hash, sigencode=ecdsa.util.sigencode_der)
    public_key = private_key.get_verifying_key()
    pubkey = public_key.to_string()
    return (pubkey, sig)

'''
def sign_inputs(algo, secexp, inputs, outputs):
    # This is reworked but backward compatible (non-streaming) method from Electrum
    signatures = []
    for i in range(len(inputs)):
        addr_n = inputs[i].address_n
        print addr_n
    
        tx = raw_tx(inputs, outputs, for_sig=i)
        tx_hash = tools.Hash(tx)
        signatures.append(sign_input(algo, secexp, addr_n, tx_hash))
    return signatures
'''