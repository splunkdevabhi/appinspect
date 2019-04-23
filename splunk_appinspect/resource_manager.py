# Copyright 2018 Splunk Inc. All rights reserved.

# Python Standard Libraries
from collections import defaultdict
import contextlib
import threading
import weakref


class ResourceManagerContext(object):

    def __init__(self, manager, context):
        self.manager = manager
        self.context = context
        self._resources = dict()
        self._locks = defaultdict(threading.Lock)

    def release(self):
        for resource in self._resources.values():
            resource.release()

    def resource(self):
        return None

    def keys(self):
        return self.manager.resource_types.keys()

    def get(self, attrname):
        with self._locks[attrname]:
            if attrname in self.manager.resource_types and attrname not in self._resources:
                self._resources[attrname] = self.manager.resource_types[attrname](self.context)
                self._resources[attrname].setup()
            if attrname in self._resources:
                return self._resources[attrname].resource()
            else:
                raise KeyError("No such resource defined in context: {} ([{}])".format(
                    attrname, self.manager.resource_types.keys()))

    def __getitem__(self, attrname):
        return self.get(attrname)

    def __contains__(self, resource_name):
        return resource_name in self.manager.resource_types


class ResourceManager(object):

    def __init__(self, **resource_types):
        self.resource_types = resource_types

    def add_resource_type(self, name, klass):
        self.resource_types[name] = klass

    def available_resources(self):
        return self.resource_types.keys()

    def __contains__(self, resource_name):
        return resource_name in self.resource_types

    @contextlib.contextmanager
    def context(self, ctx_args={}):
        ctx = ResourceManagerContext(self, ctx_args)
        try:
            yield ctx
        finally:
            ctx.release()


class ManagedResource(object):

    def __init__(self, ctx):
        self.context = ctx
        self._resource = None

    def resource(self):
        return self._resource

    def setup(self):
        pass

    def release(self):
        """ Clean up """
        pass
