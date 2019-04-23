# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Application content structure standards

Ensure that the application content adheres to Splunk standards.
"""

# Python Standard Libraries
import imghdr
import logging
import os
# Third-Party Libraries
import dimensions
# Custom Libraries
import splunk_appinspect


report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.2.1")
def check_app_icon_is_png(app, reporter):
    """Check that static/appIcon is a png file"""
    relative_file_path = ["static", "appIcon.png"]
    if app.file_exists(*relative_file_path):
        file_path = os.path.join(*relative_file_path)
        if imghdr.what(app.get_filename(*relative_file_path)) != "png":
            reporter_output = ("static/appIcon must be a png file. File: {}"
                               ).format(file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter.fail("static/appIcon.png does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.2.1")
def check_app_icon_dimensions(app, reporter):
    """Check that static/appIcon is 36x36px or less"""
    relative_file_path = ["static", "appIcon.png"]
    if app.file_exists(*relative_file_path):
        file_path = os.path.join(*relative_file_path)
        width, height, type, path = dimensions.dimensions(app.get_filename(*relative_file_path))
        if width > 36 or height > 36:
            reporter_output = ("static/appIcon.png should be 36x36 or less, but was"
                               " detected as {}x{}. File: {}"
                               ).format(width,
                                        height,
                                        file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter.fail("static/appIcon.png does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.2.1")
def check_app_icon_2x_is_png(app, reporter):
    """Check that static/appIcon_2x is a png file"""
    relative_file_path = ["static", "appIcon_2x.png"]
    if app.file_exists(*relative_file_path):
        file_path = os.path.join(*relative_file_path)
        if imghdr.what(app.get_filename(*relative_file_path)) != "png":
            reporter_output = ("static/appIcon_2x must be a png file. File: {}"
                               ).format(file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter.fail("static/appIcon_2x.png does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.2.1")
def check_app_icon_2x_dimensions(app, reporter):
    """Check that static/appIcon_2x is 72x72px or less"""
    relative_file_path = ["static", "appIcon_2x.png"]
    if app.file_exists(*relative_file_path):
        file_path = os.path.join(*relative_file_path)
        width, height, type, path = dimensions.dimensions(app.get_filename(*relative_file_path))
        if width > 72 or height > 72:
            reporter_output = ("static/appIcon_2x.png should be 72x72 or less, but was"
                               " detected as {}x{}. File: {}"
                               ).format(width,
                                        height,
                                        file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter.fail("static/appIcon_2x.png does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.2.1")
def check_app_icon_alt_is_png(app, reporter):
    """Check that static/appIconAlt is a png file"""
    relative_file_path = ["static", "appIconAlt.png"]
    if app.file_exists(*relative_file_path):
        file_path = os.path.join(*relative_file_path)
        if imghdr.what(app.get_filename(*relative_file_path)) != "png":
            reporter_output = ("static/appIconAlt must be a png file. File: {}"
                               ).format(file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter.not_applicable("static/appIconAlt.png does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.2.1")
def check_app_icon_alt_dimensions(app, reporter):
    """Check that static/appIconAlt.png is 36x36px or less"""
    relative_file_path = ["static", "appIconAlt.png"]
    if app.file_exists(*relative_file_path):
        file_path = os.path.join(*relative_file_path)
        width, height, type, path = dimensions.dimensions(app.get_filename(*relative_file_path))
        if width > 36 or height > 36:
            reporter_output = ("static/appIconAlt.png should be 36x36 or less, but was"
                               " detected as {}x{}. File: {}"
                               ).format(width,
                                        height,
                                        file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter.not_applicable("static/appIconAlt.png does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.2.1")
def check_app_icon_alt_2x_is_png(app, reporter):
    """Check that static/appIconAlt_2x is a png file"""
    relative_file_path = ["static", "appIconAlt_2x.png"]
    if app.file_exists(*relative_file_path):
        file_path = os.path.join(*relative_file_path)
        if imghdr.what(app.get_filename(*relative_file_path)) != "png":
            reporter_output = ("static/appIconAlt_2x must be a png file. File: {}"
                               ).format(file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter.not_applicable("static/appIconAlt_2x.png does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.2.1")
def check_app_icon_alt_2x_dimensions(app, reporter):
    """Check that static/appIconAlt_2x.png is 72x72px or less"""
    relative_file_path = ["static", "appIconAlt_2x.png"]
    if app.file_exists(*relative_file_path):
        file_path = os.path.join(*relative_file_path)
        width, height, type, path = dimensions.dimensions(app.get_filename(*relative_file_path))
        if width > 72 or height > 72:
            reporter_output = ("static/appIconAlt_2x.png should be 72x72 or less, but was"
                               " detected as {}x{}. File: {}"
                               ).format(width,
                                        height,
                                        file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter.not_applicable("static/appIconAlt_2x.png does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.2.1")
def check_app_logo_is_png(app, reporter):
    """Check that static/appLogo is a png file"""
    relative_file_path = ["static", "appLogo.png"]
    if app.file_exists(*relative_file_path):
        file_path = os.path.join(*relative_file_path)
        if imghdr.what(app.get_filename(*relative_file_path)) != "png":
            reporter_output = ("static/appLogo must be a png file. File: {}"
                               ).format(file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter.not_applicable("static/appLogo.png does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.2.1")
def check_app_logo_dimensions(app, reporter):
    """Check that static/appLogo.png is 160x40px or less"""
    relative_file_path = ["static", "appLogo.png"]
    if app.file_exists(*relative_file_path):
        file_path = os.path.join(*relative_file_path)
        width, height, type, path = dimensions.dimensions(app.get_filename(*relative_file_path))
        if width > 160 or height > 40:
            reporter_output = ("static/appLogo.png should be 160x40 or less, but was"
                               " detected as {}x{}. File: {}"
                               ).format(width,
                                        height,
                                        file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter.not_applicable("static/appLogo.png does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.2.1")
def check_app_logo_2x_is_png(app, reporter):
    """Check that static/appLogo_2x is a png file"""
    relative_file_path = ["static", "appLogo_2x.png"]
    if app.file_exists(*relative_file_path):
        file_path = os.path.join(*relative_file_path)
        if imghdr.what(app.get_filename(*relative_file_path)) != "png":
            reporter_output = ("static/appLogo_2x must be a png file. File: {}"
                               ).format(file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter.not_applicable("static/appLogo_2x.png does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.2.1")
def check_app_logo_2x_dimensions(app, reporter):
    """Check that static/appLogo_2x.png is 320x80px or less"""
    relative_file_path = ["static", "appLogo_2x.png"]
    if app.file_exists(*relative_file_path):
        file_path = os.path.join(*relative_file_path)
        width, height, type, path = dimensions.dimensions(app.get_filename(*relative_file_path))
        if(width > 320 or
                height > 80):
            reporter_output = ("static/appLogo_2x.png should be 320x80 or less, but was"
                               " detected as {}x{}. File: {}"
                               ).format(width,
                                        height,
                                        file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter.not_applicable("static/appLogo_2x.png does not exist.")
