import logging
from Parser.parser import BaseParser

logging.basicConfig(level=logging.INFO)


class srx_parser(BaseParser):
    def __init__(self, configfile=None):
        super(BaseParser).__init__(configfile)
        logging.debug('Initializing Juniper SRx Parsing Module')