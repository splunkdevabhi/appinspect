# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Lookup file standards

Lookups add fields from an external source to events based on the values of fields that are already present in those events.
"""

# Python Standard Library
import logging
import os
import re
import sys
import csv
# Third-Party Libraries
# N/A
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.lookup import LookupHelper

logger = logging.getLogger(__name__)
report_display_order = 13


@splunk_appinspect.tags('splunk_appinspect')
@splunk_appinspect.cert_version(min='1.5.0')
def check_lookup_csv_is_valid(app, reporter):
    """Check that `.csv` files are not empty, have at least two columns, have
    headers with no more than 4096 characters, do not use Macintosh-style (\\r)
    line endings, have the same number of columns in every row, and contain
    only UTF-8 characters."""

    for basedir, file, ext in app.iterate_files(basedir="lookups", types=[".csv"]):
        app_file_path = os.path.join(basedir, file)
        full_file_path = app.get_filename(app_file_path)
        try:
            is_valid, rationale = LookupHelper.is_valid_csv(full_file_path)
            if not is_valid:
                reporter.fail("This .csv lookup is not formatted as valid csv."
                              " Details: {} File: {}".format(rationale, app_file_path), app_file_path)
        except Exception as err:
            logger.warn("Error validating lookup. File: {}. Error: {}"
                        .format(full_file_path, err))
            reporter.fail("Error opening and validating lookup. Please"
                          " investigate this lookup and remove it if it is not" 
                          " formatted as valid CSV. File: {}"
                          .format(app_file_path), app_file_path)
