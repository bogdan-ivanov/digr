class BaseTransformer(object):
    ESSENTIAL = False
    RECOMMENDED = False

    def __init__(self, data, config):
        self.data = data
        self.config = config

    @property
    def name(self):
        return self.__class__.__name__

    def setup(self):
        pass

    def run(self):
        pass
