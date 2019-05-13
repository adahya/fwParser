import logging, re, pprint, json
from Parser.parser import BaseParser
from .Configuration import FortigateConfiguration

pp = pprint.PrettyPrinter(indent=4)

logging.basicConfig(level=logging.INFO)
conf_re = '^#config-version=([a-zA-Z0-9]*)-([0-9.]*)-FW-(build[0-9-]*):opmode=([0-1]):vdom=([0-1]):user=([A-Za-z_-]*)$'


class fortigate_parser(BaseParser):
    config = dict()

    def __init__(self, configfile=None):
        super(fortigate_parser, self).__init__(configfile)
        self.Type = 'FortiGate'
        logging.debug('Initializing Fortigate Parsing Module')

    def parse(self):
        self.__clean_config()
        queue = []
        for line in self.lines:
            line = line.lstrip()
            if line.startswith(('config', 'edit',)):
                command, section = line.split(' ', 1)
                if 'vdom' in section and len(queue) == 1:
                    continue
                else:
                    queue.append(section)

            elif line.startswith(('end', 'next',)):
                queue.pop()
            elif line.startswith(('set', 'unset')):

                def _process_set(line, config, i=0):
                    if i < len(queue):
                        if queue[i] not in config.keys():
                            config[queue[i]] = dict()
                        _process_set(line, config[queue[i]], i + 1)
                    elif i == len(queue):
                        unset = False
                        if line.startswith('set'):
                            line = line[4:]
                            if 'set' not in config.keys():
                                config['set'] = dict()
                            command, args = line.split(' ', 1)
                            config['set'][command] = args
                        elif line.startswith('unset'):
                            line = line[6:]
                            unset = True
                            if 'unset' not in config.keys():
                                config['unset'] = dict()
                            if ' ' in line:
                                command, args = line.split(' ', 1)
                            else:
                                command = line
                                args = ''
                            config['unset'][command] = args or ''

                _process_set(line, self.config)
        with open('output.json', 'w') as f:
            json.dump(self.config, f, sort_keys=False, indent=4)

    def __clean_config(self):
        self.lines = self.lines[self.__index_of_header():]
        while ':'.join(hex(ord(x))[2:] for x in self.lines[-1]) != "65:6e:64":
            self.lines.pop()
        temp = []
        for line in self.lines:
            modified_line = line.lstrip()
            if line is '':
                continue
            elif modified_line.startswith(('config', 'end', 'edit', 'next', 'set', 'unset',)):
                temp.append(line)
            elif len(temp) > 1:
                temp[-1] = "{} {}".format(temp[-1], line)
        self.lines = temp

    def __index_of_header(self):
        p = re.compile(conf_re)
        for i, line in enumerate(self.lines):
            if p.match(line):
                m = p.match(line)
                self.model = m.group(1)
                self.version = m.group(2)
                self.build = m.group(3)
                self.vdom_enabled = True if m.group(5) is '1' else False
                return i
        return None

    def get_json_config(self):
        return self.config

    def get_config_obj(self):
        return FortigateConfiguration(self.get_json_config())