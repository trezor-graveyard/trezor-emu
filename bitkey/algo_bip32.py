class AlgoBIP32(object):
    @classmethod
    def get_secexp_from_seed(cls, seed):
        raise NotImplemented("Not implemented")

    @classmethod
    def init_master_private_key(cls, secexp):
        raise NotImplemented("Not implemented")

    @classmethod
    def init_master_public_key(cls, secexp):
        raise NotImplemented("Not implemented")

    @classmethod
    def get_new_address(cls, secexp, n):
        raise NotImplemented("Not implemented")

    @classmethod
    def get_private_key(cls, secexp, n):
        raise NotImplemented("Not implemented")
