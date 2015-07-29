import types_pb2 as types

BTC = types.CoinType(
    maxfee_kb=100000,  # == 0.001 BTC/kB
    coin_name='Bitcoin',
    coin_shortcut='BTC',
    address_type=0,
    address_type_p2sh=5,
)

TEST = types.CoinType(
    maxfee_kb=10000000,  # == 0.1 TEST/kB
    coin_name='Testnet',
    coin_shortcut='TEST',
    address_type=111,
    address_type_p2sh=196,
)

NMC = types.CoinType(
    maxfee_kb=10000000,  # == 0.1 NMC/kB
    coin_name='Namecoin',
    coin_shortcut='NMC',
    address_type=52,
    address_type_p2sh=5,
)

LTC = types.CoinType(
    maxfee_kb=1000000,  # == 0.01 LTC/kB
    coin_name='Litecoin',
    coin_shortcut='LTC',
    address_type=48,
    address_type_p2sh=5,
)

DOGE = types.CoinType(
    maxfee_kb=1000000000,  # == 10 DOGE/kB
    coin_name='Dogecoin',
    coin_shortcut='DOGE',
    address_type=30,
    address_type_p2sh=22,
)

DRK = types.CoinType(
    maxfee_kb=100000,  # == 0.001 DASH/kB
    coin_name='Dash',
    coin_shortcut='DASH',
    address_type=76,
    address_type_p2sh=16,
)

types = {
    'Bitcoin': BTC,
    'Testnet': TEST,
    'Namecoin': NMC,
    'Litecoin': LTC,
    'Dogecoin': DOGE,
    'Darkcoin': DRK,
}
