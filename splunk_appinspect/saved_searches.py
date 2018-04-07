# Copyright 2016 Splunk Inc. All rights reserved.

# Python Standard Libraries
import os
import re
from distutils.util import strtobool
# Custom Libraries
import saved_searches_configuration_file


class SavedSearch:
    """Represents a saved search."""

    def __init__(self, name):
        self.name = name

        self.args = {}
        self.cron_schedule = None
        self.disabled = str(0)
        self.dispatch_earliest_time = None
        self.dispatch_latest_time = None
        self.searchcmd = ""

    @property
    def cron_schedule(self):
        return self.cron_schedule

    @cron_schedule.setter
    def cron_schedule(self, cron_schedule):
        self.cron_schedule = cron_schedule

    @property
    def dispatch_earliest_time(self):
        return self.dispatch_earliest_time

    @dispatch_earliest_time.setter
    def dispatch_earliest_time(self, dispatch_earliest_time):
        self.dispatch_earliest_time = dispatch_earliest_time

    @property
    def dispatch_latest_time(self):
        return self.dispatch_latest_time
    
    @property
    def is_disabled(self):
        return strtobool(self.disabled)

    @dispatch_latest_time.setter
    def dispatch_latest_time(self, dispatch_latest_time):
        self.dispatch_latest_time = dispatch_latest_time

    def is_real_time_search(self):
        real_time_regex_string = "^rt"
        dispatch_earliest_time_is_real_time_search = (re.search(real_time_regex_string,
                                                                self.dispatch_earliest_time)
                                                      if self.dispatch_earliest_time
                                                      else False)
        dispatch_latest_time_is_real_time_search = (re.search(real_time_regex_string,
                                                              self.dispatch_latest_time)
                                                    if self.dispatch_latest_time
                                                    else False)
        return (dispatch_earliest_time_is_real_time_search or
                dispatch_latest_time_is_real_time_search)


class SavedSearches:
    """Represents a savedsearches.conf file from default/savedsearches.conf."""

    def __init__(self, app):
        self.app = app
        self.commands_conf_file_path = app.get_filename('default',
                                                        'savedsearches.conf')

    def configuration_file_exists(self):
        return self.app.file_exists('default', 'savedsearches.conf')

    def get_configuration_file(self):
        return self.app.get_config('savedsearches.conf',
                                   config_file=saved_searches_configuration_file.SavedSearchesConfigurationFile())

    def searches(self):

        search_list = []

        for section in self.get_configuration_file().section_names():

            search = SavedSearch(section)

            for key, value in self.get_configuration_file().items(section):
                search.args[key] = [value]

                if key.lower() == "cron_schedule":
                    search.cron_schedule = value

                if key.lower() == "disabled":
                    search.disabled = value

                if key.lower() == "dispatch.earliest_time":
                    search.dispatch_earliest_time = value

                if key.lower() == "dispatch.latest_time":
                    search.dispatch_latest_time = value

                if key.lower() == "search":
                    search.searchcmd = value

            search_list.append(search)

        return search_list
