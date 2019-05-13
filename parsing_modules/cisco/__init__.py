import logging
from Parser.parser import BaseParser

logging.basicConfig(level=logging.INFO)


class cisco_asa_parser(BaseParser):
    def __init__(self, configfile=None):
        super(BaseParser).__init__(configfile)
        logging.debug('Initializing Cisco ASA Parsing Module')