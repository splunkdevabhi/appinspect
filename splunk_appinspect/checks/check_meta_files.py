# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Meta file standards

Ensure that all meta files located in the **/metadata** folder are well formed and valid.
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


@splunk_appinspect.cert_version(min="1.6.1")
@splunk_appinspect.tags("splunk_appinspect")
def check_validate_no_duplicate_stanzas_in_meta_files(app, reporter):
    """Check that `.meta` files do not have duplicate
    [stanzas](https://docs.splunk.com/Splexicon:Stanza).
    """
    stanzas_regex = r"^\[(.*)\]"
    stanzas = app.search_for_pattern(stanzas_regex, types=[".meta"])
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
def check_meta_file_parsing(app, reporter):
    """Check that all `.meta` files parse with no trailing whitespace after
    continuations with no duplicate stanzas or options.
    """
    for directory, file, ext in app.iterate_files(types=[".meta"]):
        file_path = os.path.join(directory, file)
        meta = app.get_meta(file, directory=directory)
        for err, line, section in meta.errors:
            reporter_output = ("{} at line {} in [{}] of {}."
                               " File: {}, Line: {}."
                               ).format(err,
                                        line,
                                        section,
                                        file,
                                        file_path,
                                        line)
            reporter.fail(reporter_output, file_path, line)
