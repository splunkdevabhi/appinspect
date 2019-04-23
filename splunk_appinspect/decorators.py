# Copyright 2018 Splunk Inc. All rights reserved.

"""Each of these add metadata to the function they wrap. This metadata is then 
used by the Check object that encloses it.
"""


def cert_version(min='1.0', max=None):
    """
    Allows specifying which checks should be run at a given certification level. Both min and max define an _inclusive_ range, compared as strings
    """
    def wrap(check):
        check.min_version = min
        check.max_version = max
        return check
    return wrap


def tags(*args):
    """Allows specifying of different groups of checks via tags"""
    def wrap(check):
        check.tags = args
        return check
    return wrap


def deferred(*args):
    """
    Designates that the decorated check should be deferred and run at the end of the run
    """
    # Though bumped to the end, there is still no order- merely tiers. Order can be
    # trivially supported, but I'm reluctant to allow easy ordering of tests- in my
    # opinion, relying on test order makes for more fragile tests and a less maintainable
    # test suite.
    def wrap(check):
        check.deferred = True
        return check
    return wrap


def display(report_display_order=1000):
    """
    Allows specifying an order for checks to appear within a group
    """
    def wrap(check):
        check.report_display_order = report_display_order
        return check
    return wrap
