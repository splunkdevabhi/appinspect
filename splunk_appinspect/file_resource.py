# Copyright 2016 Splunk Inc. All rights reserved.

# Python Standard Libraries
import os


class FileResource(object):

    def __init__(self, file_path, ext="", app_file_path=""):
        self.file_path = file_path
        self.app_file_path = app_file_path
        self.ext = ext
        self.tags = []

    def exists(self):
        return os.path.isfile(self.file_path)
