# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Saved search standards

[Saved searches](http://docs.splunk.com/Documentation/Splunk/latest/SearchTutorial/Aboutsavingandsharingreports)
are defined in a [savedsearches.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Savedsearchesconf) file located at `default/savedsearches.conf`.
"""

# Python Standard Libraries
import logging
from distutils.util import strtobool
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.cron_expression import CronExpression

report_display_order = 13
logger = logging.getLogger(__name__)


@splunk_appinspect.tags('splunk_appinspect', 'savedsearches')
@splunk_appinspect.cert_version(min="1.1.8")
@splunk_appinspect.display(report_display_order=1)
def check_saved_search_conf_exists(app, reporter):
    """Check that a `savedsearches.conf` file exists at
    `default/savedsearches.conf`.
    """
    saved_searches = app.get_saved_searches()
    if saved_searches.configuration_file_exists():
        pass
    else:
        reporter_output = ("No savedsearches.conf file exists.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'savedsearches')
@splunk_appinspect.cert_version(min="1.1.8")
def check_saved_searches_are_not_disabled(app, reporter):
    """Check that saved searches are enabled."""
    saved_searches = app.get_saved_searches()
    if saved_searches.configuration_file_exists():
        for search in saved_searches.searches():
            if search.disabled == "1":
                message = ("The search [{}] in savedsearches.conf is"
                           " disabled.").format(search.name)
                reporter.warn(message)


@splunk_appinspect.tags('splunk_appinspect', 'savedsearches')
@splunk_appinspect.cert_version(min="1.1.8")
def check_saved_search_specifies_a_search(app, reporter):
    """Check that saved searches have a search string specified."""

    saved_searches = app.get_saved_searches()
    if saved_searches.configuration_file_exists():
        for search in saved_searches.searches():
            if search.searchcmd == "":
                mess = "The search '{}' in savedsearches.conf does not specify a search.".format(
                    search.name)
                reporter.warn(mess)


@splunk_appinspect.tags('splunk_appinspect')
@splunk_appinspect.cert_version(min="1.1.8")
def check_for_emails_in_saved_search(app, reporter):
    """Check that email alerts (action.email.to) set in `savedsearches.conf`
    do not have a default value.
    """

    saved_searches = app.get_saved_searches()
    if saved_searches.configuration_file_exists():
        for search in saved_searches.searches():
            for key, value in search.args.iteritems():
                if key == "action.email.to":
                    reporter_output = ("The saved search {} has specified the"
                                       " `action.email.to` property with a"
                                       " provided value. This should be left"
                                       " empty or removed."
                                       ).format(search.name)
                    if len(value) > 0:
                        reporter.fail(reporter_output)
    else:
        reporter_output = ("No savedsearches.conf exists.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.20")
def check_for_real_time_saved_searches(app, reporter):
    """Check that no real-time pre-index saved searches are being used in
    `savedsearches.conf`.  Real-time per-index saved searches are extremely
    system intensive and should be avoided.
    """
    # http://docs.splunk.com/Documentation/Splunk/latest/Search/Specifyrealtimewindowsinyoursearch
    if app.file_exists("default", "savedsearches.conf"):
        saved_searches = app.get_saved_searches()
        for saved_search in saved_searches.searches():
            if saved_search.is_real_time_search() and saved_search.is_disabled:
                reporter_output = ("The stanza [{}] contains a real-time"
                                   " search however it is disabled.").format(saved_search.name)
                reporter.warn(reporter_output)
            elif saved_search.is_real_time_search() and not saved_search.is_disabled:
                reporter_output = ("The stanza [{}] contains a real-time"
                                   " search. Please disable real-time searches"
                                   " by default or utilize indexed real time"
                                   " searches.").format(saved_search.name)
                reporter.manual_check(reporter_output, 'default/savedsearches.conf')
            elif not saved_search.is_real_time_search():
                reporter_output = ("The stanza [{}] does not contain a real-time search.").format(saved_search.name)
                reporter.not_applicable(reporter_output)
    else:
        reporter_output = ("`default/savedsearches.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "manual")
@splunk_appinspect.cert_version(min="1.1.20")
def check_for_gratuitous_cron_scheduling(app, reporter):
    """Check that `default/savedsearches.conf` searches are cron scheduled
    reasonably. Less than five asterisks should be used.
    """
    if app.file_exists("default", "savedsearches.conf"):
        saved_searches = app.get_saved_searches()
        cron_schedule_saved_search = [saved_search
                                      for saved_search
                                      in saved_searches.searches()
                                      if saved_search.cron_schedule]

        invalid_cron_schedule_saved_searches = []
        gratuitous_cron_schedule_saved_searches = []
        for saved_search in cron_schedule_saved_search:
            try:
                exp = CronExpression(saved_search.cron_schedule)
                if not exp.is_valid():
                    invalid_cron_schedule_saved_searches.append(saved_search)
                elif exp.is_high_occurring():
                        gratuitous_cron_schedule_saved_searches.append(saved_search)
            except:
                invalid_cron_schedule_saved_searches.append(saved_search)

        if cron_schedule_saved_search:
            if gratuitous_cron_schedule_saved_searches:
                for saved_search in gratuitous_cron_schedule_saved_searches:
                    reporter_output = ("The saved search [{}] was detected with"
                                       " a high-occuring cron_schedule. Please"
                                       " evaluate if `cron_schedule = {}`"
                                       " appropriate."
                                       ).format(saved_search.name,
                                                saved_search.cron_schedule)
                    reporter.fail(reporter_output)
            if invalid_cron_schedule_saved_searches:
                for saved_search in invalid_cron_schedule_saved_searches:
                    reporter_output = ("The saved search [{}] was detected with"
                                       " an invalid cron_schedule. Please"
                                       " evaluate if `cron_schedule = {}`"
                                       " valid."
                                       ).format(saved_search.name,
                                                saved_search.cron_schedule)
                    reporter.fail(reporter_output)
        else:
            reporter_output = ("No saved searches with a cron schedule were"
                               " detected.")
            reporter.not_applicable(reporter_output)

    else:
        reporter_output = ("`default/savedsearches.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.3.2")
def check_for_empty_saved_search_description(app, reporter):
    """Check that `default/savedsearches.conf` has no description properties
    that are empty.
    """
    saved_searches = app.get_saved_searches()
    if saved_searches.configuration_file_exists():
        saved_searches_conf_file = saved_searches.get_configuration_file()
        for section in saved_searches_conf_file.sections():
            if (section.has_option("description") and
                    section.get_option("description").value.strip() == ""):
                reporter_output = ("The stanza [{}] contains an empty"
                                   " description property. Please fill this in"
                                   " with the appropriate information or remove"
                                   " the property.").format(section.name)
                reporter.fail(reporter_output)
    else:
        reporter_output = ("`default/savedsearches.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.1")
def check_for_sched_saved_searches_earliest_time(app, reporter):
    """Check that if a savedsearch.conf stanza contains scheduling options
    it does contain a dispatch.earliest_time
    """
    if app.file_exists("default", "savedsearches.conf"):
        savedsearches_config = app.get_config("savedsearches.conf")
        for section in savedsearches_config.sections():
            if section.has_option("enableSched") and \
                    strtobool(section.get_option("enableSched").value.strip()):
                if section.has_option("dispatch.earliest_time"):
                    continue
                reporter_output = ("The saved search [{}] doesn't contain dispatch.earliest_time."
                                   "It is prohibited to specify scheduled searches that "
                                   "don't specify a dispatch.earliest_time in Splunk Cloud"
                                   ).format(section.name)
                reporter.fail(reporter_output, file_name="default/savedsearches.conf")
    else:
        reporter_output = "No `default/savedsearches.conf`file exists"
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.1")
def check_for_sched_saved_searches_latest_time(app, reporter):
    """Check that if a savedsearch.conf stanza contains scheduling options
    it does contain a dispatch.latest_time
    """
    if app.file_exists("default", "savedsearches.conf"):
        savedsearches_config = app.get_config("savedsearches.conf")
        for section in savedsearches_config.sections():
            if section.has_option("enableSched") and \
                    strtobool(section.get_option("enableSched").value.strip()):
                if section.has_option("dispatch.latest_time"):
                    continue
                reporter_output = ("The saved search [{}] doesn't contain dispatch.latest_time."
                                   "It is better to add a dispatch.latest_time "
                                   "when specify scheduled searches in Splunk Cloud"
                                   ).format(section.name)
                reporter.warn(reporter_output, file_name="default/savedsearches.conf")
    else:
        reporter_output = "No `default/savedsearches.conf`file exists"
        reporter.not_applicable(reporter_output)