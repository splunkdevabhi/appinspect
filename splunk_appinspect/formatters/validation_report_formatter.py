# Copyright 2018 Splunk Inc. All rights reserved.


class ValidationReportFormatter(object):

    def __init__(self):
        pass

    def format(self, validation_report):
        error_output = "Derived Formatter classes should override this"
        raise NotImplementedError(error_output)
