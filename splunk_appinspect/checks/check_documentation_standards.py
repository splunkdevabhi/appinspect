# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Documentation standards
"""

# Python Standard Libraries
import codecs
import logging
import os
import re
# Third-Party Libraries
import langdetect
# Custom Libraries
import splunk_appinspect

report_display_order = 50
logger = logging.getLogger(__name__)

def find_readmes(app):
    # This is surprisingly complex- an app may have a README file that's
    # documentation. It may also have a README directory that contains
    # conf files.  We could potentially also have multiple readme files,
    # for example for different languages, installation, etc.

    # Heuristic: find all plain files in the root directory that
    # match start with "readme", case-insensitive
    candidates = [f
                  for f in os.listdir(app.app_dir)
                  if(os.path.isfile(os.path.join(app.app_dir, f)) and
                     re.match(r'(?i)^readme', f))]
    return candidates


@splunk_appinspect.tags('splunk_appinspect', 'appapproval')
@splunk_appinspect.cert_version(min='1.0.0')
@splunk_appinspect.display(report_display_order=1)
def check_basic_readme(app, reporter):
    """Check that the app has a <APP_DIR>/README file that includes
    version support, system requirements, installation, configuration,
    troubleshooting and running of the app, or a link to online documentation.
    """
    readmes = find_readmes(app)
    if len(readmes) == 0:
        reporter_output = ("No README was found.")
        reporter.fail(reporter_output)
    else:
        found_readme_with_content = False
        for readme in readmes:
            try:
                with codecs.open(os.path.join(app.app_dir, readme), encoding='utf-8') as file:
                    contents = file.read()
                    if len(contents.strip()) > 0:
                        found_readme_with_content = True
                        break
            except:
                pass
        reporter_output = ("README file(s) found but appear to be empty.")
        reporter.assert_fail(found_readme_with_content, reporter_output)

@splunk_appinspect.tags('splunk_appinspect', 'appapproval', 'manual')
@splunk_appinspect.cert_version(min='1.0.0')
@splunk_appinspect.display(report_display_order=8)
def check_documentation_language(app, reporter):
    """Check that documentation is in English."""
    readmes = find_readmes(app)
    if len(readmes) == 0:
        reporter.not_applicable("README not found")
        return

    for readme in readmes:
        try:
            with codecs.open(os.path.join(app.app_dir, readme), encoding='utf-8') as file:
                contents = file.read()
                if len(contents.strip()) == 0:
                    reporter.not_applicable("README file is empty")
                    continue
                lang = langdetect.detect(contents)
                reporter_output = ('Language for README appears to be in "{}",'
                                   ' not "en". Please verify this manually.'
                                   ' File: {}').format(lang, readme)
                reporter.assert_manual_check(lang == 'en', reporter_output)
        except Exception:
            reporter_output = ("Could not detect language of README file."
                               " File: {}".format(readme))
            reporter.manual_check(reporter_output, readme)


@splunk_appinspect.tags('splunk_appinspect', 'appapproval', 'manual')
@splunk_appinspect.cert_version(min='1.0.0')
@splunk_appinspect.display(report_display_order=9)
def check_editing_and_proofreading(app, reporter):
    """Check that documentation is free of major editing and
    proofreading (spelling, grammar, punctuation) issues.
    """
    # TODO: Might be able to use a grammar checker (like
    # http://pypi.python.org/pypi/language-check) to give advice
    reporter.manual_check("Documentation will be read during code review.")


@splunk_appinspect.tags('splunk_appinspect', 'manual')
@splunk_appinspect.cert_version(min='1.0.0')
@splunk_appinspect.display(report_display_order=7)
def check_documented_included_open_source(app, reporter):
    """Check that all open source components used in developing the app are
    listed in the app's README files with the version number and a link to the
    project's website.
    """
    reporter.manual_check("Documentation will be read during code review.")


@splunk_appinspect.tags('splunk_appinspect', 'manual')
@splunk_appinspect.cert_version(min='1.0.0')
@splunk_appinspect.display(report_display_order=3)
def check_search_acceleration(app, reporter):
    """Check that use of
    [report acceleration](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutsummaryindexing),
    search acceleration, or summary indexing is explained in the app's
    documentation.
    """
    # TODO: Only warn if searches are accelerated or summary indexes are built.
    if app.file_exists('default', 'savedsearches.conf'):
        reporter.manual_check(
            "App has a savedsearches.conf, verify that it is documented.")
    else:
        reporter.not_applicable("No savedsearches.conf file exists.")


@splunk_appinspect.tags('splunk_appinspect', 'manual')
@splunk_appinspect.cert_version(min='1.0.0')
@splunk_appinspect.display(report_display_order=2)
def check_custom_commands(app, reporter):
    """Check that use of [custom commands](https://dev.splunk.com/view/python-sdk/SP-CAAAEU2)
    is explained in the app's documentation.
    """
    if app.file_exists('default', 'commands.conf'):
        reporter.manual_check(
            "Documentation will be read during code review.")
    else:
        reporter.not_applicable("No commands.conf file exists.")


@splunk_appinspect.tags('splunk_appinspect', 'manual')
@splunk_appinspect.cert_version(min='1.0.0')
@splunk_appinspect.display(report_display_order=5)
def check_dependencies(app, reporter):
    """Check that prerequisites of the app are explained in the app's
    documentation. All prerequisites must be either
    packaged with your app, or be available on Splunkbase as a certified app.
    """
    reporter.manual_check("Documentation will be read during code review.")

@splunk_appinspect.tags('splunk_appinspect', 'manual')
@splunk_appinspect.cert_version(min="1.5.0")
def check_archived_files(app, reporter):
    """Check that any compressed archives within the main release that
    need extracting are explained in the app's documentation.
    """
    archived_files = list(app.iterate_files(types=[".gz", ".tgz", ".spl", ".zip", ".tar"]))
    if archived_files:
        for directory, file, ext in archived_files:
            reporter_output = ("Found archived file: {}. Please make sure any archived files in the app are documented."
                               ).format(file)
            reporter.manual_check(reporter_output, os.path.join(directory, file))
    else:
        reporter_output = "No archived files found in app."
        reporter.not_applicable(reporter_output)
