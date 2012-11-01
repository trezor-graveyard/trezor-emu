class AlgoBIP32(object):
    
    @classmethod
    def init_master_private_key(cls, seed):
        raise NotImplemented
    
    @classmethod
    def init_master_public_key(cls, seed):
        raise NotImplemented

    @classmethod
    def get_new_address(cls, seed, n):
        raise NotImplemented
    
    @classmethod
    def get_private_key(cls, seed, n):
        raise NotImplemented