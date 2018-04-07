# Copyright 2016 Splunk Inc. All rights reserved.

"""
### JSON file standards
"""

# Python Standard Library
import json
import os
import logging
# Third-Party
# N/A
# Custom Modules
import splunk_appinspect


logger = logging.getLogger(__name__)
report_display_order = 13


@splunk_appinspect.tags('splunk_appinspect', 'cloud')
@splunk_appinspect.cert_version(min='1.1.0')
def check_validate_json_data_is_well_formed(app, reporter):
    """Check that all JSON files are well formed."""

    for dir, file, ext in app.iterate_files(types=['.json']):
        current_file_relative_path = os.path.join(dir, file)
        current_file_full_path = app.get_filename(dir, file)

        with open(current_file_full_path, "r") as f:
            current_file_contents = f.read()

        try:
            json_object = json.loads(current_file_contents)
        except Exception as e:
            reporter_output = ("Malformed JSON file found. "
                               "File: {} "
                               "Error: {}").format(current_file_relative_path, str(e))
            reporter.fail(reporter_output)
