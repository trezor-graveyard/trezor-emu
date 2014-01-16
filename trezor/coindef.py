import types_pb2 as types

BTC = types.CoinType(
    maxfee_kb=10000,  # == 0.0001 BTC/kB
    coin_name='Bitcoin',
    coin_shortcut='BTC',
    address_type=0,
    ser_private=0x0488ADE4,
    ser_public=0x0488B21E,
)

tBTC = types.CoinType(
    maxfee_kb=10000000,  # == 0.1 tBTC/kB
    coin_name='Testnet',
    coin_shortcut='tBTC',
    address_type=111,
    ser_private=0x04358394,
    ser_public=0x043587CF,
)

NMC = types.CoinType(
    maxfee_kb=10000000,  # == 0.1 NMC/kB
    coin_name='Namecoin',
    coin_shortcut='NMC',
    address_type=52,
    ser_private=0x0488ADE4, # xprv 
    ser_public=0x0488B21E,  # xpub
)

LTC = types.CoinType(
    maxfee_kb=10000000,  # == 0.1 LTC/kB
    coin_name='Litecoin',
    coin_shortcut='LTC',
    address_type=48,
    ser_private=0x019D9CFE,
    ser_public=0x019dA462,
)

types = {
    'Bitcoin': BTC,
    'Testnet': tBTC,
    'Namecoin': NMC,
    'Litecoin': LTC,
}
