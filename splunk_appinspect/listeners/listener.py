# Copyright 2018 Splunk Inc. All rights reserved.


class Listener(object):

    def handle_event(self, event, *args):
        eventname = 'on_' + event
        if hasattr(self, eventname):
            getattr(self, eventname)(*args)
