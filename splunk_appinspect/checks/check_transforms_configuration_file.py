# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Transforms.conf File Standards

Ensure that the transforms.conf file located in the `default` folder is well
formed and valid.

- [transforms.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Transformsconf)
"""

# Python Standard Library
import logging
# Custom Libraries
import splunk_appinspect
import regex as re

report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.12")
def check_all_lookups_are_used(app, reporter):
    """Check that all files in the /lookups directory are referenced in
    `transforms.conf`.
    """
    lookup_file_names = set()
    transforms_reference_file_names = set()
    for dir, file, ext in app.iterate_files(basedir="lookups"):
        if file.endswith(".default"):
            loookup_file_no_default_suffix = file[:len(file) - len(".default")]
            lookup_file_names.add(loookup_file_no_default_suffix)
        else:
            lookup_file_names.add(file)

    if app.file_exists("default", "transforms.conf"):
        transforms = app.transforms_conf()
        for section in transforms.sections():
            if section.has_option("filename"):
                lookup_file_name = section.get_option("filename").value
                transforms_reference_file_names.add(lookup_file_name)
        for file in (lookup_file_names - transforms_reference_file_names):
            reporter_output = ("Lookup file {} is not referenced in"
                               " transforms.conf").format(file)
            reporter.fail(reporter_output)
    else:
        reporter.not_applicable("No transforms.conf in app")


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.12")
def check_capture_groups_in_transforms(app, reporter):
    """Check that all capture groups are used in transforms.conf.
    Groups not used for capturing should use the
    [non-capture group syntax](http://docs.splunk.com/Documentation/Splunk/latest/Knowledge/AboutSplunkregularexpressions#Non-capturing_group_matching)
    """
    if app.file_exists("default", "transforms.conf"):
        transforms = app.transforms_conf()
        for section in transforms.sections():
            if section.has_option("REGEX") and section.has_option("FORMAT"):
                regex = section.get_option("REGEX").value
                fmt = section.get_option("FORMAT").value
                try:
                    # Splunk regular expressions are PCRE (Perl Compatible Regular Expressions)
                    # re does not support PCRE, so use regex as re, see import part
                    pattern = re.compile(regex)
                except re.error:
                    reporter_output = ("The following stanza contains invalid `REGEX` property."
                                       " Stanza: [{}]"
                                       " REGEX: {}").format(section.name,
                                                            regex)
                    reporter.fail(reporter_output, file_name="default/transforms.conf")
                    return
                unused_groups = []

                for i in range(pattern.groups):
                    if fmt.find("$" + str(i + 1)) < 0:
                        unused_groups.append("$" + str(i + 1))

                if len(unused_groups) > 0:
                    url = "http://docs.splunk.com/Documentation/Splunk/latest/Knowledge/AboutSplunkregularexpressions#Non-capturing_group_matching"
                    reporter_output = ("The following stanza contains `FORMAT`"
                                       " property that does not match its `REGEX` property, missing: {}."
                                       " Stanza: [{}]"
                                       " REGEX: {}"
                                       " FORMAT: {}."
                                       " If you don't want to capture any group in your regexp,"
                                       " please use a non-capturing expression,"
                                       " see {} for details.").format(unused_groups,
                                                                      section.name,
                                                                      regex,
                                                                      fmt,
                                                                      url)
                    reporter.fail(reporter_output, file_name="default/transforms.conf")
    else:
        reporter.not_applicable("No transforms.conf in app")
