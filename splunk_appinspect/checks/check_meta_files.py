# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Meta File Standards

Ensure that all meta files located in the `metadata` folder are well formed and
valid.
"""

# Python Standard Library
import collections
import logging
import os
import re
import stat
# Custom Libraries
import splunk_appinspect

report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.cert_version(min="1.1.0")
@splunk_appinspect.tags("splunk_appinspect")
def check_validate_no_duplicate_stanzas(app, reporter):
    """Check that `.meta` files do not have duplicate
    [stanzas](https://docs.splunk.com/Splexicon:Stanza).
    """
    for relative_filepath, full_filepath in app.get_filepaths_of_files(types=[".meta"]):
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
def check_meta_file_parsing(app, reporter):
    """Check that all `.meta` files parse with no trailing whitespace after 
    continuations with no duplicate stanzas or options.
    """
    for directory, file, ext in app.iterate_files(types=[".meta"]):
        meta = app.get_meta(file, directory=directory)
        for err, line, section in meta.errors:
            reporter_output = ("{} at line {} in [{}] of {}"
                               ).format(err, line, section, file)
            reporter.fail(reporter_output)
