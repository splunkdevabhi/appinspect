# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Props Configuration file standards

Ensure that all props.conf files located in the `default` (or `local`) folder are well
formed and valid.

- [props.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf)
- [transforms.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Transformsconf)
"""

# Python Standard Library
import logging
import re
import os
# Custom Libraries
import splunk_appinspect

report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.8")
def check_props_conf_has_transforms_option_and_transforms_conf_exist(app, reporter):
    """Check that there is a 'transforms.conf' file when TRANSFORM- options
    are defined in `props.conf`.
    """
    settings_key_regex_pattern = "TRANSFORMS-"

    if app.file_exists("default", "props.conf"):
        file_path = os.path.join("default", "props.conf")
        props_config = app.props_conf()
        sections_with_transforms = list(
            props_config.sections_with_setting_key_pattern(settings_key_regex_pattern))

        if len(sections_with_transforms) > 0:
            for section in sections_with_transforms:
                for setting in section.settings_with_key_pattern(settings_key_regex_pattern):
                    if app.file_exists("default", "transforms.conf"):
                        pass
                    else:
                        reporter_output = ("No transforms.conf exists for "
                                           "[{}], {}. File: {}, Line: {}."
                                           ).format(section.name,
                                                    setting.name,
                                                    file_path,
                                                    section.lineno)
                        reporter.fail(reporter_output, file_path, section.lineno)
        else:
            reporter_output = "No TRANSFORMS- properties were declared."
            reporter.not_applicable(reporter_output)
    else:
        reporter_output = "No props.conf file exists."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.8")
def check_props_conf_has_transforms_option_and_transforms_conf_has_matching_stanza(app, reporter):
    """Check that TRANSFORM- options in `props.conf` have associated stanzas in
    `transforms.conf` file.
    """
    settings_key_regex_pattern = "TRANSFORMS-"

    if app.file_exists("default", "props.conf"):
        file_path = os.path.join("default", "props.conf")
        props_config = app.props_conf()
        props_sections_with_transforms = list(
            props_config.sections_with_setting_key_pattern(settings_key_regex_pattern))

        if len(props_sections_with_transforms) > 0:
            if app.file_exists("default", "transforms.conf"):
                transforms_config = app.transforms_conf()
                for props_section in props_sections_with_transforms:
                    for setting in props_section.settings_with_key_pattern(settings_key_regex_pattern):
                        for props_transforms_stanza_name in setting.value.split(","):
                            if transforms_config.has_section(props_transforms_stanza_name.strip()):
                                pass  # Do nothing, test passed
                            else:
                                reporter_output = ("Transforms.conf does not"
                                                   " contain a [{}] stanza to match"
                                                   " props.conf [{}] {}={}."
                                                   " File: {}, Line: {}."
                                                   ).format(props_transforms_stanza_name.strip(),
                                                            props_section.name,
                                                            setting.name,
                                                            setting.value,
                                                            file_path,
                                                            props_section.lineno)
                                reporter.fail(reporter_output, file_path, props_section.lineno)
            else:
                reporter_output = "No transforms.conf exists. File: {}".format(file_path)
                reporter.fail(reporter_output, file_path)
        else:
            reporter_output = "No TRANSFORMS- properties were declared."
            reporter.not_applicable(reporter_output)
    else:
        reporter_output = "No props.conf file exists."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.8")
def check_props_conf_has_report_option_and_transforms_conf_exist(app, reporter):
    """Check that there is a 'transforms.conf' file when REPORT- options are
    defined in `props.conf`.
    """
    settings_key_regex_pattern = "REPORT-"

    config_file_paths = app.get_config_file_paths("props.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            props_config = app.props_conf(directory)
            sections_with_transforms = list(
                props_config.sections_with_setting_key_pattern(settings_key_regex_pattern))

            if len(sections_with_transforms) > 0:
                for section in sections_with_transforms:
                    for setting in section.settings_with_key_pattern(settings_key_regex_pattern):
                        if app.file_exists(directory, "transforms.conf"):
                            pass
                        else:
                            reporter_output = ("No transforms.conf exists for "
                                               "[{}], {}. File: {}, Line: {}."
                                               ).format(section.name,
                                                        setting.name,
                                                        file_path,
                                                        section.lineno)
                            reporter.fail(reporter_output, file_path, section.lineno)
            else:
                reporter_output = "No REPORT- properties were declared."
                reporter.not_applicable(reporter_output)
    else:
        reporter_output = "No props.conf file exists."
        reporter.not_applicable(reporter_output)


# TODO: Add documentation link
@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.8")
def check_props_conf_has_report_option_and_transforms_conf_has_matching_stanza(app, reporter):
    """Check that each REPORT- in `props.conf` has an associated stanza in
    `transforms.conf` file.
    """
    settings_key_regex_pattern = "REPORT-"

    config_file_paths = app.get_config_file_paths("props.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            props_config = app.props_conf(directory)
            props_sections_with_transforms = list(
                props_config.sections_with_setting_key_pattern(settings_key_regex_pattern))

            if len(props_sections_with_transforms) > 0:
                if app.file_exists(directory, "transforms.conf"):
                    transforms_config = app.transforms_conf(dir=directory)
                    for props_section in props_sections_with_transforms:
                        for setting in props_section.settings_with_key_pattern(settings_key_regex_pattern):
                            for props_transforms_stanza_name in setting.value.split(","):
                                if transforms_config.has_section(props_transforms_stanza_name.strip()):
                                    pass  # Do nothing, test passed
                                else:
                                    reporter_output = ("Transforms.conf does not"
                                                       " contain a [{}] stanza to match"
                                                       " props.conf [{}] {}={}."
                                                       " File: {}, Line: {}."
                                                       ).format(props_transforms_stanza_name.strip(),
                                                                props_section.name,
                                                                setting.name,
                                                                setting.value,
                                                                file_path,
                                                                props_section.lineno)
                                    reporter.fail(reporter_output, file_path, props_section.lineno)
                else:
                    reporter_output = "No transforms.conf exists. File: {}".format(file_path)
                    reporter.fail(reporter_output, file_path)
            elif directory == 'default':
                reporter_output = "No REPORT- properties were declared."
                reporter.not_applicable(reporter_output)
    else:
        reporter_output = "No props.conf file exists."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.8")
def check_props_conf_has_report_option_and_transforms_conf_has_required_option(app, reporter):
    """Check that REPORT- options in props.conf, have either DELIMS or REGEX
    options in the matching transforms.conf stanza.
    """
    settings_key_regex_pattern = "REPORT-"

    config_file_paths = app.get_config_file_paths("props.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            props_config = app.props_conf(directory)
            props_sections_with_transforms = list(
                props_config.sections_with_setting_key_pattern(settings_key_regex_pattern))

            if len(props_sections_with_transforms) > 0:
                if app.file_exists(directory, "transforms.conf"):
                    transforms_config = app.transforms_conf(directory)
                    for props_section in props_sections_with_transforms:
                        # Check if KV_MODE = xml or json, if so these are extracted automatically so N/A
                        # See: ACD-1516
                        if (props_section.has_option("KV_MODE") and
                            props_section.get_option("KV_MODE").value in ["json", "xml"]):
                            reporter_output = ("REPORT- property stanza has KV_MODE"
                                               " = {} so DELIMS/REGEX not required."
                                               ).format(props_section.get_option("KV_MODE").value)
                            reporter.not_applicable(reporter_output)
                            continue
                        for setting in props_section.settings_with_key_pattern(settings_key_regex_pattern):
                            for props_transforms_stanza_name in setting.value.split(","):
                                if transforms_config.has_section(props_transforms_stanza_name.strip()):
                                    if (transforms_config.get_section(
                                        props_transforms_stanza_name.strip()).has_setting_with_pattern("delims") or
                                            transforms_config.get_section(
                                            props_transforms_stanza_name.strip()).has_setting_with_pattern("regex")):
                                        pass  # Do nothing, the test has succeeded
                                    else:
                                        reporter_output = ("Transforms.conf [{}] does not"
                                                           " specify DELIMS or REGEX"
                                                           " to match props.conf [{}], {}."
                                                           " File: {}, Line: {}."
                                                           ).format(props_transforms_stanza_name.strip(),
                                                                    props_section.name,
                                                                    setting.name,
                                                                    file_path,
                                                                    props_section.lineno)
                                        reporter.fail(reporter_output, file_path, props_section.lineno)
                                else:
                                    reporter_output = ("Transforms.conf does not"
                                                       " contain a [{}] stanza to match"
                                                       " props.conf [{}] {}={}."
                                                       " File: {}, Line: {}."
                                                       ).format(props_transforms_stanza_name.strip(),
                                                                props_section.name,
                                                                setting.name,
                                                                setting.value,
                                                                file_path,
                                                                props_section.lineno)
                                    reporter.fail(reporter_output, file_path, props_section.lineno)
                else:
                    reporter_output = "No transforms.conf exists. File: {}".format(file_path)
                    reporter.fail(reporter_output, file_path)
            else:
                reporter_output = "No REPORT- properties were declared."
                reporter.not_applicable(reporter_output)
    else:
        reporter_output = "No props.conf file exists."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.16")
def check_props_conf_regex_stanza_name_followed_by_double_colon(app, reporter):
    """Check that the props.conf stanzas (delayedrule, host, rule, or source)
    are followed by `::`.

For example:

 * `[host::nyc*]`
 * `[rule::bar_some]`
    """
    config_file_paths = app.get_config_file_paths("props.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            props_conf = app.props_conf(directory)

            # if starts with host, source, rule or delayedrule then it is a
            # props.conf stanza name that uses regex
            regex_stanza_names = ["host", "delayedrule", "rule", "source"]

            regex_stanza_patterns = ["^{}".format(regex_stanza_name)
                                     for regex_stanza_name
                                     in regex_stanza_names]
            regex_stanza_patterns_str = "|".join(regex_stanza_patterns)
            regex_stanza_patterns_regex_object = re.compile(regex_stanza_patterns_str,
                                                            re.MULTILINE | re.IGNORECASE)

            valid_regex_stanza_patterns = ["^{}::".format(regex_stanza_pattern)
                                           for regex_stanza_pattern
                                           in regex_stanza_names]
            valid_regex_stanza_patterns_str = "|".join(valid_regex_stanza_patterns)
            valid_regex_stanza_patterns_regex_object = re.compile(valid_regex_stanza_patterns_str,
                                                                  re.MULTILINE | re.IGNORECASE)

            invalid_props_stanza_names = [(stanza.name, stanza.lineno)
                                          for stanza
                                          in props_conf.sections()
                                          if(re.search(regex_stanza_patterns_regex_object, stanza.name) and
                                             not re.search(valid_regex_stanza_patterns_regex_object, stanza.name))]
            if invalid_props_stanza_names:
                for invalid_props_stanza_name, lineno in invalid_props_stanza_names:
                    reporter_output = ("Missing colon(s) detected for a props.conf"
                                       " regex stanza name. Make sure it uses `::`."
                                       " Stanza Name: {}. File: {}, Line: {}."
                                       ).format(invalid_props_stanza_name,
                                                file_path,
                                                lineno)
                    reporter.fail(reporter_output, file_path, lineno)
    else:
        reporter_output = "No props.conf file exists."
        reporter.not_applicable(reporter_output)
