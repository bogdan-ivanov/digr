class BaseTransformer(object):
    def __init__(self, data, config):
        self.data = data
        self.config = config

    def setup(self):
        pass

    def run(self):
        pass
