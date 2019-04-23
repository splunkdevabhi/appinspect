# Copyright 2018 Splunk Inc. All rights reserved.

# Python Standard Libraries
import logging


def create_logger(level=logging.WARN):
    """
    Basic setup of app inspect logging.
    """
    logging.basicConfig(level=level)
    log = logging.getLogger("splunk_appinspect")
    return log
