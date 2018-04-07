# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Configuration file standards

Ensure that all configuration files located in the `default` folder are well 
formed and valid.
"""

# Python Standard Library
import collections
import logging
import os
import re
import stat
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.splunk_defined_conf_file_list import SPLUNK_DEFINED_CONFS

report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.cert_version(min="1.1.0")
@splunk_appinspect.tags("splunk_appinspect")
def check_validate_no_duplicate_stanzas(app, reporter):
    """Check that no duplicate 
    [stanzas](https://docs.splunk.com/Splexicon:Stanza) exist in .conf files.
    """
    for relative_filepath, full_filepath in app.get_filepaths_of_files(types=[".conf"], basedir=['default', 'local']):
        stanzas_found = collections.defaultdict(int)

        with open(full_filepath, "r") as f:
            current_file_contents = f.read()

        stanzas_regex = re.compile("^\[(.*)\]",
                                   re.IGNORECASE | re.MULTILINE)
        stanzas = re.findall(stanzas_regex, current_file_contents)
        for stanza in stanzas:
            stanzas_found[stanza] += 1

        for key, value in stanzas_found.iteritems():
            if value > 1:
                reporter_output = ("Duplicate {} stanzas were found in file: {}"
                                   ).format(key, relative_filepath)
                reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.12")
def check_config_file_parsing(app, reporter):
    """Check that all config files parse cleanly- no trailing whitespace after 
    continuations, no duplicated stanzas or options.
    """
    for directory, file, ext in app.iterate_files(types=[".conf"],  basedir=['default', 'local']):
        conf = app.get_config(file, dir=directory)
        for err, line, section in conf.errors:
            reporter_output = ("{} at line {} in [{}] of {}"
                               ).format(err, line, section, file)
            reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_no_default_stanzas(app, reporter):
    """Check that app does not contain any .conf files that create global
    definitions using the `[default]` stanza. 
    """
    # Added whitelist support because people are making poor life choices and
    # building splunk features that require the use of the `default` stanza
    # The white list conf files using the default stanza will be supported, but
    # not condoned
    conf_file_whitelist = ["savedsearches.conf"]
    for directory, file_name, ext in app.iterate_files(types=[".conf"], basedir=['default', 'local']):
        if file_name not in conf_file_whitelist:
            conf = app.get_config(file_name, dir=directory)
            for section_name in ['default', 'general', 'global']:
                if conf.has_section(section_name) and _is_not_empty_section(conf.get_section(section_name)):
                    if _is_splunk_defined_conf(file_name):
                        reporter_output = ("{} stanza was found in file: {}. "
                                           "Custom app-specific conf files should avoid [default], [general], [global] "
                                           "stanzas or properties outside of a stanza (treated as default/global). "
                                           "This is discouraged because they may cause some confusion "
                                           "for same stanzas defined by Splunk"
                                           .format(section_name, os.path.join(directory, file_name)))
                        reporter.fail(reporter_output, os.path.join(directory, file_name))


def _is_not_empty_section(section):
    return len(section.items()) > 0


def _is_splunk_defined_conf(file_name):
    return file_name not in SPLUNK_DEFINED_CONFS
