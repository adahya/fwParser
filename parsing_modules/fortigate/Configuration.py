from Parser.Configuration import AbstractConfiguration


class FortigateConfiguration(AbstractConfiguration):
    __routes_table = None

    def __init__(self, config):
        self.raw_config = config
        self.is_vdom()

    def is_vdom(self):
        if self.virtualizeFw:
            return self.virtualizeFw
        if 'vdom' in self.raw_config.keys():
            self.virtualizeFw = True
        else:
            self.virtualizeFw = False
        return self.virtualizeFw

    def get_vdoms(self):
        if self.virtualizeFw:
            return list(self.raw_config['vdom'].keys())
        elif not self.virtualizeFw:
            return []
        return None

    def get_virtualize_instances(self):
        return self.get_vdoms()

    def get_routing_table(self, instance=None):
        if self.__routes_table:
            return self.__routes_table
        if self.get_vdoms() and self.get_vdoms() is not []:
            for vdom in self.get_vdoms():
                if 'router static' in self.raw_config['vdom'][vdom].keys():

                    print(self.raw_config['vdom'][vdom]['router static'])
