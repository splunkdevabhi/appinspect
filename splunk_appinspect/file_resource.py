# Copyright 2018 Splunk Inc. All rights reserved.

# Python Standard Libraries
import os
import bs4
import logging

logger = logging.getLogger(__name__)


class FileResource(object):

    def __init__(self, file_path, ext="", app_file_path="", file_name=""):
        self.file_path = file_path
        self.app_file_path = app_file_path
        self.ext = ext
        self.file_name = file_name
        self.tags = []

    def exists(self):
        return os.path.isfile(self.file_path)

    def parse(self, fmt):
        try:
            if fmt in ['xml', 'lxml-xml', 'lxml']:
                return bs4.BeautifulSoup(open(self.file_path), "lxml")
        except Exception, e:
            logging.error(str(e))
            raise
        else:
            logging.error("{} file is not supported!".format(fmt))
            raise Exception("{} file is not supported!".format(fmt))

