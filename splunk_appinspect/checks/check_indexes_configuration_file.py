# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Indexes.conf File Standards

Ensure that the index configuration file located in the `default` folder are
well formed and valid.

- [indexes.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Indexesconf)
"""

# Python Standard Library
import logging
# Custom Libraries
import splunk_appinspect

report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.cert_version(min="1.1.23")
@splunk_appinspect.tags("splunk_appinspect")
def check_indexes_conf_does_not_exist(app, reporter):
    """Check that the app does not create indexes."""
    if app.file_exists("default", "indexes.conf"):
        reporter_output = ("Apps and add-ons should not create indexes. Indexes"
                           " should only be defined by Splunk System"
                           " Administrators to meet the data storage and"
                           " retention needs of the installation. Consider"
                           " using Tags or Source Types to identify data"
                           " instead index location.")
        reporter.fail(reporter_output, file_name="default/indexes.conf")


@splunk_appinspect.cert_version(min="1.1.7")
@splunk_appinspect.tags("splunk_appinspect", "cloud")
def check_validate_default_indexes_not_modified(app, reporter):
    """Check that no default Splunk indexes are modified by the app."""
    default_indexes = ["_audit", "_internal", "_introspection" "_thefishbucket",
                       "history", "main", "provider-family:hadoop",
                       "splunklogger", "summary", "volume:_splunk_summaries"]
    if app.file_exists("default", "indexes.conf"):
        indexes_config = app.get_config("indexes.conf")
        for section in indexes_config.section_names():
            if section in default_indexes:
                reporter_output = ("The following index was modified: {}"
                                   ).format(section)
                reporter.fail(reporter_output, file_name="default/indexes.conf")
    else:
        reporter_output = "No `default/indexes.conf`file exists"
        reporter.not_applicable(reporter_output)

@splunk_appinspect.cert_version(min="1.5.0")
@splunk_appinspect.tags("splunk_appinspect")
def check_index_definition_has_required_options(app, reporter):
    """Check that all index definitions exist all required options including:
    homePath, coldPath, and thawedPath.
    """
    required_options = ["homePath", "coldPath", "thawedPath"]
    filter_section_prefix = ("provider-family:", "provider:", "volume:")
    virtual_index_required_option = "vix.provider"

    if app.file_exists("default", "indexes.conf"):
        indexes_config = app.get_config("indexes.conf")
        for section in indexes_config.sections():
            # not check default stanza
            if section.name is "default":
                continue
            # not check provider-family, provider and volume
            if section.name.startswith(filter_section_prefix):
                continue
            # not check virtual index
            if section.has_option(virtual_index_required_option):
                continue
            for required_option in required_options:
                if not section.has_option(required_option):
                    reporter_output = ("The {} index definition does not have the required option: {}."
                                       ).format(section.name, required_option)
                    reporter.fail(reporter_output, file_name="default/indexes.conf")
    else:
        reporter_output = "No `default/indexes.conf`file exists"
        reporter.not_applicable(reporter_output)


@splunk_appinspect.cert_version(min="1.5.0")
@splunk_appinspect.tags("cloud")
def check_index_definition_does_not_contain_invoke_scripts_options(app, reporter):
    """Check that all index definitions does not contain invoke scripts options including:
    warmToColdScript, coldToFrozenScript, and vix.command.
    """
    invoke_scripts_options = ("warmToColdScript", "coldToFrozenScript", "vix.command")

    if app.file_exists("default", "indexes.conf"):
        indexes_config = app.get_config("indexes.conf")
        for section in indexes_config.sections():
            for invoke_scripts_option in invoke_scripts_options:
                if section.has_option(invoke_scripts_option):
                    reporter_output = ("The {} index definition contains option: {}."
                                       "It is not permitted to use scripts to affect retention in Splunk Cloud."
                                       ).format(section.name, invoke_scripts_options)
                    reporter.fail(reporter_output, file_name="default/indexes.conf")
    else:
        reporter_output = "No `default/indexes.conf`file exists"
        reporter.not_applicable(reporter_output)
