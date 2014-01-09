import types_pb2 as types

BTC = types.CoinType(
    maxfee_kb=1000000,  # == 0.01 BTC/kB
    coin_name='Bitcoin',
    coin_shortcut='BTC',
    address_type=0,
)

tBTC = types.CoinType(
    maxfee_kb=10000000,  # == 0.1 tBTC/kB
    coin_name='Testnet',
    coin_shortcut='tBTC',
    address_type=111,
)

NMC = types.CoinType(
    maxfee_kb=10000000,  # == 0.1 NMC/kB
    coin_name='Namecoin',
    coin_shortcut='NMC',
    address_type=52,
)

LTC = types.CoinType(
    maxfee_kb=10000000,  # == 0.1 LTC/kB
    coin_name='Litecoin',
    coin_shortcut='LTC',
    address_type=48,
)

types = {
    'Bitcoin': BTC,
    'Testnet': tBTC,
    'Namecoin': NMC,
    'Litecoin': LTC,
}