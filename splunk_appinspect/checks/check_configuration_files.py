# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Configuration file standards

Ensure that all configuration files located in the **/default** folder are well formed and valid.
"""

# Python Standard Library
import collections
import logging
import os
import re
import stat
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.configuration_parser import InvalidSectionError
from splunk_appinspect.splunk_defined_conf_file_list import SPLUNK_DEFINED_CONFS
from splunk_appinspect import app_util

report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.cert_version(min="1.6.1")
@splunk_appinspect.tags("splunk_appinspect")
def check_validate_no_duplicate_stanzas_in_conf_files(app, reporter):
    """Check that no duplicate
    [stanzas](https://docs.splunk.com/Splexicon:Stanza) exist in .conf files.
    """
    stanzas_regex = r"^\[(.*)\]"
    stanzas = app.search_for_pattern(stanzas_regex, types=[".conf"], basedir=['default', 'local'])
    stanzas_found = collections.defaultdict(list)

    for fileref_output, match in stanzas:
        filepath, line_number = fileref_output.rsplit(":", 1)
        file_stanza = (filepath, match.group())
        stanzas_found[file_stanza].append(line_number)

    for key, linenos in stanzas_found.iteritems():
        if len(linenos) > 1:
            for lineno in linenos:
                reporter_output = ("Duplicate {} stanzas were found. "
                                   "File: {}, Line: {}."
                                   ).format(key[1],
                                            key[0],
                                            lineno)
                reporter.fail(reporter_output, key[0], lineno)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.12")
def check_config_file_parsing(app, reporter):
    """Check that all config files parse cleanly- no trailing whitespace after
    continuations, no duplicated stanzas or options.
    """
    for directory, filename, ext in app.iterate_files(types=[".conf"], basedir=['default', 'local']):
        conf = app.get_config(filename, dir=directory)
        file_path = os.path.join(directory, filename)
        for err, lineno, section in conf.errors:
            reporter_output = ("{} at line {} in [{}] of {}. "
                               "File: {}, Line: {}."
                               ).format(err,
                                        lineno,
                                        section,
                                        filename,
                                        file_path,
                                        lineno)
            reporter.fail(reporter_output, file_path, lineno)


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

    for directory, filename, ext in app.iterate_files(types=[".conf"], basedir=['default', 'local']):
        if filename not in conf_file_whitelist:
            file_path = os.path.join(directory, filename)
            try:
                conf = app.get_config(filename, dir=directory)
                for section_name in ['default', 'general', 'global']:

                        if conf.has_section(section_name) and _is_not_empty_section(conf.get_section(section_name)):
                            if _is_splunk_defined_conf(filename):
                                lineno = conf.get_section(section_name).lineno
                                reporter_output = ("{} stanza was found in {}. "
                                                   "Please remove any [default], [general], [global] stanzas or properties "
                                                   "outside of a stanza (treated as default/global) "
                                                   "from conf files defined by Splunk."
                                                   "These stanzas/properties are not permitted "
                                                   "because they modify global settings outside the context of the app."
                                                   "File: {}, Line: {}."
                                                   ).format(section_name,
                                                            file_path,
                                                            file_path,
                                                            lineno)
                                reporter.fail(reporter_output, file_path, lineno)
            except InvalidSectionError as e:
                reporter_output = "file config malformed. exception = {}".format(e.message)
                reporter.fail(reporter_output, file_path)
            except Exception:
                raise


def _is_not_empty_section(section):
    return len(section.items()) > 0


def _is_splunk_defined_conf(file_name):
    return file_name in SPLUNK_DEFINED_CONFS


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.6.0")
def check_manipulation_outside_of_app_container(app, reporter):
    """Check that app conf files do not point to files outside the app container. 
    Because hard-coded paths won't work in Splunk Cloud, we don't consider to 
    check absolute paths.
    """
    reporter_template = ("Manipulation outside of the app container was found in "
                         "file {}; See stanza `{}`, "
                         "key `{}` value `{}`. File: {}, Line: {}."
                        )
    app_name = app.package.working_artifact_name

    conf_parameter_arg_regex = re.compile('''"[^"]+"|'[^']+'|[^"'\s]+''')
    conf_check_list = {'app.conf': ['verify_script'],
                        'distsearch.conf': ['genKeyScript'],
                        'restmap.conf': ['pythonHandlerPath'],
                        'authentication.conf': ['scriptPath'],
                        'server.conf': ['certCreateScript'],
                        'limits.conf': ['search_process_mode']
                        }
    for directory, filename, ext in app.iterate_files(types=['.conf'], basedir=['default', 'local']):
        if not filename in conf_check_list:
            continue
        conf = app.get_config(filename, dir=directory)
        for section in conf.sections():
            full_filepath = os.path.join(directory, filename)
            for option in section.settings():
                key = option.name
                value = option.value
                lineno = option.lineno
                if not key in conf_check_list[filename]:
                    continue
                for path in conf_parameter_arg_regex.findall(value):
                    if app_util.is_manipulation_outside_of_app_container(path, app_name):
                        reporter_output = reporter_template.format(full_filepath,
                                                                   section.name,
                                                                   key,
                                                                   value,
                                                                   full_filepath,
                                                                   lineno)
                        reporter.fail(reporter_output, full_filepath, lineno)