# Copyright 2016 Splunk Inc. All rights reserved.


def unique(a):
    """ return the list with duplicate elements removed """
    return list(set(a))


def intersect(a, b):
    """ return the intersection of two lists """
    return list(set(a) & set(b))


def union(a, b):
    """ return the union of two lists """
    return list(set(a) | set(b))


def count_iter(iterator):
    """Returns a count of items, yielded by an iterator"""
    return reduce(lambda acc, x: acc + 1, iterator, 0)
