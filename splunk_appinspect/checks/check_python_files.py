# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Python file standards
"""

# Python Standard Library
import logging
import os
# Third-Party
# N/A
# Custom Modules
import splunk_appinspect

logger = logging.getLogger(__name__)

report_display_order = 40


@splunk_appinspect.tags('cloud', 'manual')
@splunk_appinspect.cert_version(min='1.1.22')
def check_for_python_files(app, reporter):
    """Check if the app contains python scripts."""
    application_files = list(app.iterate_files(types=[".py"]))
    if application_files:
        for directory, file, ext in application_files:
            current_file_relative_path = os.path.join(directory, file)
            reporter_output = ("python script found."
                               " File: {}").format(current_file_relative_path)
            reporter.manual_check(reporter_output, current_file_relative_path)

    else:
        reporter_output = "No python scripts found in app."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'cloud')
@splunk_appinspect.cert_version(min='1.0.0')
def check_for_compiled_python(app, reporter):
    """Check that there are no `.pyc` or `.pyo` files included in the app."""
    for dir, file, ext in app.iterate_files(types=['.pyc', '.pyo']):
        current_file_relative_path = os.path.join(dir, file)
        reporter_output = ("A Compiled Python file was detected. File: {}"
                           ).format(current_file_relative_path)
        reporter.fail(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min='1.1.17')
def check_for_possible_threading(app, reporter):
    """Check for the use of threading, and multiprocesses. Threading must be
    used with discretion and not negatively affect the Splunk installation as a
    whole.
    """
    questionable_statements_regex = ["from\s+os\s+import\s+(?:.*,)?\s*fork(?!\w+)",
                                     "from\s+os\s+import\s+(?:.*,)?\s*forkpty(?!\w+)",
                                     "os\s*\.\s*fork",
                                     "from\s+os\s+import\s+(?:.*,)?\s*spawn",
                                     "os\s*\.\s*spawn",
                                     "from\s+os\s+import\s+(?:.*,)?\s*setsid(?!\w+)",
                                     "os\s*\.\s*setsid",
                                     "from\s+distutils\s+import\s+(?:.*,)?\s*spawn(?!\w+)",
                                     "distutils\s*\.\s*spawn"]
    matches = app.search_for_patterns(questionable_statements_regex,
                                      types=['.py'])
    python_files = list(app.iterate_files(types=['.py']))

    if python_files:
        for (fileref_output, match) in matches:
            filename, line_number = fileref_output.rsplit(":", 1)
            reporter_output = ("The following line will be inspected during code review."
                               " Match: {}"
                               " File: {}"
                               " Line Number: {}"
                               ).format(match.group(), filename, line_number)
            reporter.manual_check(reporter_output, filename, line_number)
    else:
        reporter_output = ("No python files found.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "cloud", "security", "manual")
@splunk_appinspect.cert_version(min="1.5.1")
def check_built_in_import_function(app, reporter):
    """Check that the python `__import__` method is not used in a way that
    can be exploited (e.g., __import__(conf_setting) is at risk of code 
    injection).
    """
    # This method shouldn't be used because imports should be explicit to 
    # prevent execution of unintended code. If you're dynamically loading 
    # libraries via strings there is some concern
    # https://docs.python.org/2/library/functions.html#__import__
    # Nice SO dicussion on this here:
    # http://stackoverflow.com/questions/28231738/import-vs-import-vs-importlib-import-module
    # http://stackoverflow.com/questions/2724260/why-does-pythons-import-require-fromlist
    # https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html
    all_python_files = list(app.iterate_files(types=[".py"]))

    import_patterns = ["__import__"]
    matches = app.search_for_patterns(import_patterns,
                                      types=[".py"])
    if len(all_python_files) > 0:
        for (fileref_output, match) in matches:
            filepath, line_number = fileref_output.rsplit(":", 1)
            reporter_output = ("The `__import__` function was detected being"
                               " used. Please use the `import` keyword instead."
                               " Third-Party libraries are exempt from this"
                               " requirement."
                               " File: {}"
                               " Line Number: {}").format(filepath, line_number)
            file_dirname = os.path.dirname(filepath)
            # Check for dynamic imports that could be exploited for command injection
            reporter.manual_check(reporter_output, filepath, line_number)
    else:
        reporter_output = ("No python files detected.")
        reporter.not_applicable(reporter_output)
