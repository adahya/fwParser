import logging
from Parser.parser import BaseParser

logging.basicConfig(level=logging.INFO)


class pan_parser(BaseParser):
    def __init__(self, configfile=None):
        super(BaseParser).__init__(configfile)
        logging.debug('Initializing PaloAlto Firewall Parsing Module')


class pan_panorama_parser(BaseParser):
    def __init__(self, configfile=None):
        super(BaseParser).__init__(configfile)
        logging.debug('Initializing PaloAlto Panorama Parsing Module')