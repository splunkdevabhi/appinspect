# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Saved search standards

Saved searches are defined in a **savedsearches.conf** file located in the **/default** directory of the app. For more, see <a href="http://docs.splunk.com/Documentation/Splunk/latest/SearchTutorial/Aboutsavingandsharingreports" target="_blank">Save and share your reports</a> and <a href="http://docs.splunk.com/Documentation/Splunk/latest/Admin/Savedsearchesconf">savedsearches.conf</a>.
"""

# Python Standard Libraries
import logging
import os
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.cron_expression import CronExpression
from splunk_appinspect.splunk import normalizeBoolean

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
        file_path = os.path.join("default", "savedsearches.conf")
        for search in saved_searches.searches():
            if search.disabled == "1":
                lineno = search.args["disabled"][1]
                message = ("The search [{}] in savedsearches.conf is"
                           " disabled. File: {}, Line: {}."
                           ).format(search.name,
                                    file_path,
                                    lineno)
                reporter.warn(message, file_path, lineno)


@splunk_appinspect.tags('splunk_appinspect', 'savedsearches')
@splunk_appinspect.cert_version(min="1.1.8")
def check_saved_search_specifies_a_search(app, reporter):
    """Check that saved searches have a search string specified."""

    saved_searches = app.get_saved_searches()
    if saved_searches.configuration_file_exists():
        file_path = os.path.join("default", "savedsearches.conf")
        for search in saved_searches.searches():
            if search.searchcmd == "":
                mess = "The search '{}' in savedsearches.conf" \
                       " does not specify a search. File: {}," \
                       "Line: {}." \
                    .format(search.name,
                            file_path,
                            search.lineno)
                reporter.warn(mess, file_path, search.lineno)


@splunk_appinspect.tags('splunk_appinspect')
@splunk_appinspect.cert_version(min="1.1.8")
def check_for_emails_in_saved_search(app, reporter):
    """Check that email alerts (action.email.to) set in `savedsearches.conf`
    do not have a default value.
    """

    saved_searches = app.get_saved_searches()
    if saved_searches.configuration_file_exists():
        file_path = os.path.join("default", "savedsearches.conf")
        for search in saved_searches.searches():
            for key, value in search.args.iteritems():
                if key == "action.email.to":
                    reporter_output = ("The saved search {} has specified the"
                                       " `action.email.to` property with a"
                                       " provided value. This should be left"
                                       " empty or removed. File: {}, Line: {}."
                                       ).format(search.name,
                                                file_path,
                                                value[1])
                    if len(value) > 0:
                        reporter.fail(reporter_output, file_path, value[1])
    else:
        reporter_output = ("No savedsearches.conf exists.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.20")
def check_for_real_time_saved_searches(app, reporter):
    """Check that no real-time pre-index saved searches are being used in
    `savedsearches.conf`.  Real-time per-index saved searches are extremely
    system intensive and should be avoided.
    """
    # http://docs.splunk.com/Documentation/Splunk/latest/Search/Specifyrealtimewindowsinyoursearch
    if app.file_exists("default", "savedsearches.conf"):
        saved_searches = app.get_saved_searches()
        file_path = os.path.join("default", "savedsearches.conf")
        for saved_search in saved_searches.searches():
            if saved_search.is_real_time_search():
                reporter_output = ("The stanza [{}] contains a real-time"
                                   " search. File: {}, Line: {}."
                                   ).format(saved_search.name,
                                            file_path,
                                            saved_search.lineno)
                reporter.warn(reporter_output, file_path, saved_search.lineno)
            else:
                reporter_output = ("The stanza [{}] does not contain a real-time search.").format(saved_search.name)
                reporter.not_applicable(reporter_output)
    else:
        reporter_output = ("`default/savedsearches.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.5.4")
def check_for_real_time_saved_searches_for_cloud(app, reporter):
    """Check that no real-time pre-index saved searches are being used in
    `savedsearches.conf`.  Real-time per-index saved searches are extremely
    system intensive and should be avoided.
    """
    # http://docs.splunk.com/Documentation/Splunk/latest/Search/Specifyrealtimewindowsinyoursearch
    if app.file_exists("default", "savedsearches.conf"):
        saved_searches = app.get_saved_searches()
        file_path = os.path.join("default", "savedsearches.conf")
        for saved_search in saved_searches.searches():
            if saved_search.is_real_time_search() and saved_search.is_disabled:
                reporter_output = ("The stanza [{}] contains a real-time"
                                   " search, but it is disabled. File: {},"
                                   " Line: {}."
                                   ).format(saved_search.name,
                                            file_path,
                                            saved_search.lineno)
                reporter.warn(reporter_output, file_path, saved_search.lineno)
            elif saved_search.is_real_time_search() and not saved_search.is_disabled:
                reporter_output = ("The stanza [{}] contains a real-time"
                                   " search. Please disable this search. File: {},"
                                   " Line: {}."
                                   ).format(saved_search.name,
                                            file_path,
                                            saved_search.lineno)
                reporter.fail(reporter_output, file_path, saved_search.lineno)
            else:
                reporter_output = ("The stanza [{}] does not contain a real-time search.").format(saved_search.name)
                reporter.not_applicable(reporter_output)
    else:
        reporter_output = ("`default/savedsearches.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.1.20")
def check_for_gratuitous_cron_scheduling(app, reporter):
    """Check that `default/savedsearches.conf` searches are cron scheduled
    reasonably. Less than five asterisks should be used.
    """
    if app.file_exists("default", "savedsearches.conf"):
        file_path = os.path.join("default", "savedsearches.conf")
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
                    minutes_field = exp.fields[0]
                    occurrences = CronExpression._get_occurrences_in_an_hour(minutes_field)
                    gratuitous_cron_schedule_saved_searches.append((saved_search,occurrences))
            except:
                invalid_cron_schedule_saved_searches.append(saved_search)

        if cron_schedule_saved_search:
            if gratuitous_cron_schedule_saved_searches:
                for saved_search,occurrences in gratuitous_cron_schedule_saved_searches:
                    lineno = saved_search.args["cron_schedule"][1]
                    reporter_output = ("The saved search [{}] was detected with"
                                       " a high-occuring cron_schedule, i.e. During a period of an hour,"
                                       " if the search is scheduled for over 12 times, it will be"
                                       " considered as high occurring. It occurs {} times within 1 hour here."
                                       " Please evaluate whether `cron_schedule = {}`"
                                       " is appropriate. File: {}, Line: {}."
                                       ).format(saved_search.name,
                                                occurrences.count(True),
                                                saved_search.cron_schedule,
                                                file_path,
                                                lineno)
                    reporter.warn(reporter_output, file_path, lineno)
            if invalid_cron_schedule_saved_searches:
                for saved_search in invalid_cron_schedule_saved_searches:
                    lineno = saved_search.args["cron_schedule"][1]
                    reporter_output = ("The saved search [{}] was detected with"
                                       " an invalid cron_schedule. Please"
                                       " evaluate whether `cron_schedule = {}`"
                                       " is valid. File: {}, Line: {}."
                                       ).format(saved_search.name,
                                                saved_search.cron_schedule,
                                                file_path,
                                                lineno)
                    reporter.fail(reporter_output, file_path, lineno)
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
        file_path = os.path.join("default", "savedsearches.conf")
        saved_searches_conf_file = saved_searches.get_configuration_file()
        for section in saved_searches_conf_file.sections():
            if (section.has_option("description") and
                        section.get_option("description").value.strip() == ""):
                lineno = section.get_option("description").lineno
                reporter_output = ("The stanza [{}] contains an empty"
                                   " description property. Please add the"
                                   " appropriate information or remove the property."
                                   " File: {}, Line: {}."
                                   ).format(section.name,
                                            file_path,
                                            lineno)
                reporter.fail(reporter_output, file_path, lineno)
    else:
        reporter_output = ("`default/savedsearches.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.3")
def check_for_sched_saved_searches_earliest_time(app, reporter):
    """Check that if a scheduled saved search in savedsearch.conf contains dispatch.earliest_time option,
    or if a scheduled saved search with auto summary enabled contains auto_summarize.dispatch.earliest_time option
    """
    if app.file_exists("default", "savedsearches.conf"):
        savedsearches_config = app.get_config("savedsearches.conf")
        file_path = os.path.join("default", "savedsearches.conf")
        for section in savedsearches_config.sections():
            is_generating_command_search = (
                section.has_option("search") and
                section.get_option("search").value.strip().startswith("|")
            )
            if is_generating_command_search:
                # The saved search is based on a generating command which will
                # create events in real-time so earliest_time isn't needed
                continue
            if _is_scheduled_search(section) and \
                    not section.has_option("dispatch.earliest_time") and \
                    not _is_summary_search_with_earliest_time(section):
                reporter_output = ("The saved search [{}] doesn't contain dispatch.earliest_time."
                                   "It is prohibited to specify scheduled searches that "
                                   "don't specify a dispatch.earliest_time in Splunk Cloud."
                                   "File: {}, Line: {}."
                                   ).format(section.name,
                                            file_path,
                                            section.lineno)
                reporter.fail(reporter_output, file_path, section.lineno)
    else:
        reporter_output = "No `default/savedsearches.conf`file exists."
        reporter.not_applicable(reporter_output)


def _is_scheduled_search(section):
    return section.has_option("enableSched") and \
           normalizeBoolean(section.get_option("enableSched").value.strip())


def _is_summary_search_with_earliest_time(section):
    return section.has_option("auto_summarize") and \
           normalizeBoolean(section.get_option("auto_summarize").value.strip()) and \
           section.has_option("auto_summarize.dispatch.earliest_time")


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.3")
def check_for_sched_saved_searches_latest_time(app, reporter):
    """Check that if a savedsearch.conf stanza contains scheduling options
    it does contain a dispatch.latest_time
    """
    if app.file_exists("default", "savedsearches.conf"):
        savedsearches_config = app.get_config("savedsearches.conf")
        file_path = os.path.join("default", "savedsearches.conf")
        for section in savedsearches_config.sections():
            is_generating_command_search = (
                section.has_option("search") and
                section.get_option("search").value.strip().startswith("|")
            )
            if is_generating_command_search:
                # The saved search is based on a generating command which will
                # create events in real-time so earliest_time isn't needed
                continue
            if section.has_option("enableSched") and \
                    normalizeBoolean(section.get_option("enableSched").value.strip()):
                if section.has_option("dispatch.latest_time"):
                    continue
                reporter_output = ("The saved search [{}] doesn't contain dispatch.latest_time."
                                   "It is better to add a dispatch.latest_time "
                                   "when specifying scheduled searches in Splunk Cloud. "
                                   "File: {}, Line: {}."
                                   ).format(section.name,
                                            file_path,
                                            section.lineno)
                reporter.warn(reporter_output, file_path, section.lineno)
    else:
        reporter_output = "No `default/savedsearches.conf`file exists."
        reporter.not_applicable(reporter_output)
