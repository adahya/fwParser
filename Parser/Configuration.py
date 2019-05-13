from abc import ABC, abstractclassmethod


class AbstractConfiguration(ABC):
    raw_config = dict()
    virtualizeFw = None

    def get_virtualize_instances(self):
        raise NotImplementedError

    def get_routing_table(self):
        raise NotImplementedError
