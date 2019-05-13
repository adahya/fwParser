from abc import ABC, abstractclassmethod
import logging
import re

logging.basicConfig(level=logging.INFO)
logging.debug('This will get logged')


class BaseParser(ABC):
    lines = []
    more = 50
    Type = None

    def __init__(self, configfile, no_more=False):
        logging.debug('Initializing Parsing Module')
        self.filename = configfile
        self.no_more = no_more
        self.__open_file()
        self.read_file()
        self.parse()

    @property
    def object(self):
        return self.get_config_obj()

    def __open_file(self):
        self.file = open(self.filename, 'r', encoding='utf-8')

    def print(self):
        for i, line in enumerate(self.lines):
            print(line)
            if i % self.more == 0 and not self.no_more and i > self.more:
                input('-- more --')

    def read_file(self):
        for line in self.file:
            self.lines.append(line.replace('\n', ''))

    def parse(self):
        raise NotImplementedError

    def get_json_config(self):
        raise NotImplementedError

    def get_config_obj(self):
        raise NotImplementedError

    def get_routes(self):
        raise NotImplementedError



