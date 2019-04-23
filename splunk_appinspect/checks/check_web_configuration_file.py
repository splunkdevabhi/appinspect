# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Web.conf File Standards

Ensure that `web.conf` is safe for cloud deployment and that any exposed
patterns match endpoints defined by the app - apps should not expose endpoints
other than their own.

Including `web.conf` can have adverse impacts for cloud. Allow only
`[endpoint:*]` and `[expose:*]` stanzas, with expose only containing pattern=
and methods= properties.

- [web.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Webconf)
"""

# Python Standard Library
import fnmatch
import logging
import os
# Custom Libraries
import splunk_appinspect


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
@splunk_appinspect.display(report_display_order=6)
def check_web_conf(app, reporter):
    """Check that `web.conf` only defines [endpoint:*] and [expose:*]
    stanzas, with [expose:*] only containing `pattern=` and `methods=`."""
    config_file_paths = app.get_config_file_paths("web.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            web_conf = app.web_conf(directory)
            restmap_matches = None
            for section in web_conf.sections():
                if section.name.startswith("endpoint:"):
                    # [endpoint:*] stanzas are allowed, should be checked manually
                    # Note that these are part of the Module System which has been
                    # deprecated since Splunk 6.3, as of now these are still
                    # permitted for cloud but should have a corresponding script
                    # in appserver/controllers/<ENDPOINT_NAME>.py
                    endpoint_name = section.name.split("endpoint:")[1] or "<NOT_FOUND>"
                    script_path = os.path.join("appserver", "controllers",
                                               "{}.py".format(endpoint_name))

                    if app.file_exists(script_path):
                        # The python script check is covered by other checks
                        pass
                    else:
                        reporter_output = ("web.conf [endpoint:] is defined, but no"
                                           " corresponding Python script was found."
                                           " Please add a script to: {} or remove"
                                           " the [{}] stanza from web.conf"
                                           " File: {}, Line: {}."
                                           ).format(script_path,
                                                    section.name,
                                                    file_path,
                                                    section.lineno)
                        reporter.warn(reporter_output, file_path, section.lineno)
                elif section.name.startswith("expose:"):
                    # [expose:*] stanzas are allowed
                    # Fail all properties besides `pattern` and `methods`
                    for key, value in section.options.iteritems():
                        if key != "pattern" and key != "methods":
                            reporter_output = ("Only the `pattern` and `methods`"
                                               " properties are permitted for"
                                               " [expose:*] stanzas. Please remove"
                                               " this property: `{}`. Stanza: [{}]."
                                               " File: {}, Line: {}."
                                               ).format(key,
                                                        section.name,
                                                        file_path,
                                                        value.lineno)
                            reporter.fail(reporter_output, file_path, value.lineno)
                else:
                    # stanzas other than [endpoint:*] and [expose:*] are forbidden
                    reporter_output = ("Only the [endpoint:*] and [expose:*]"
                                       " stanzas are permitted in web.conf for"
                                       " cloud. Please remove this stanza from"
                                       " web.conf: [{}]. File: {}, Line: {}."
                                       ).format(section.name,
                                                file_path,
                                                section.lineno)
                    reporter.fail(reporter_output, file_path, section.lineno)
    else:
        reporter_output = "No web.conf file exists."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.5.0")
@splunk_appinspect.display(report_display_order=6)
def check_web_conf_expose_patterns_have_restmap_matches(app, reporter):
    """Check that apps only expose web endpoints that are defined by
    the Splunk App within `restmap.conf`. Each `web.conf`
    [expose:*] stanza should have the property `pattern=` which defines a url
    pattern to expose. Each url pattern exposed should correspond to a stanza
    within `restmap.conf` with a url pattern defined with the `match=`
    property, or for the case of [admin:*] stanzas a combination of `match=` and
    `members=` properties."""

    def _format_url_pattern(pattern):
        """Format to remove leading/trailing whitespace and ensure that pattern
        starts and ends with "/" or "*".

        Example: _format_url_pattern(" a/b/*/c") => "/a/b/*/c/"."""
        # Remove leading/trailing whitespace
        pattern = pattern.strip()
        # Make sure first char is "/"
        if len(pattern) == 0:
            return "/"
        if pattern[0] != "/":
            pattern = "/{}".format(pattern)
        # Make sure last char is "/" or "*"
        if len(pattern) > 1 and pattern[-1] != "/" and pattern[-1] != "*":
            pattern = "{}/".format(pattern)
        return pattern

    config_file_paths = app.get_config_file_paths("web.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            web_conf = app.web_conf(directory)
            # As needed, gather every restmap.conf match= property value
            restmap_patterns = None
            for section in web_conf.sections():
                if section.name.startswith("expose:"):
                    if section.has_option("pattern"):
                        # Format for ease of comparison
                        pattern_to_compare = _format_url_pattern(section.get_option("pattern").value)
                        # Check restmap.conf for stanzas with at least one "match"
                        # that matches this expose pattern including * (wildcards)
                        if restmap_patterns is None:
                            # Gather all patterns from restmap.conf only once
                            restmap_patterns = []
                            if app.file_exists(directory, "restmap.conf"):
                                unformatted_restmap_patterns = app.get_rest_map(dir=directory).all_restmap_patterns()
                                restmap_patterns = [_format_url_pattern(pattern)
                                                    for pattern in unformatted_restmap_patterns]

                        # Use fnmatch to find any pattern matches while respecting
                        # asterisk wildcards (e.g. "1/*/other" will match "1/4/other")
                        # Note: this is overly permissive, we are allowing a match of
                        # "a/b/*/f" with "a/b/c/d/e/f" when "*" should only match a
                        # single path element according to the docs
                        matching_restmaps = fnmatch.filter(restmap_patterns, pattern_to_compare)
                        if len(matching_restmaps) > 0:
                            # This web.conf endpoint's pattern matches at least one
                            # restmap.conf stanza match= property, check passes
                            pass
                        else:
                            lineno = section.get_option("pattern").lineno
                            reporter_output = ("web.conf found with a `pattern`"
                                               " exposed that does not correspond"
                                               " to any `match` stanza in"
                                               " restmap.conf. Apps should only"
                                               " expose endpoints that they define."
                                               " Pattern: `{}`. Please remove or edit"
                                               " this stanza: [{}]. File: {}, Line: {}."
                                               ).format(pattern_to_compare,
                                                        section.name,
                                                        file_path,
                                                        lineno)
                            # Special case: the /data/* endpoint will be exposed
                            # whether or not the app includes it in web.conf and
                            # this is currently exposed in all Add-Ons created by
                            # Add-On builder so only WARN for this case
                            if pattern_to_compare.startswith("/data/"):
                                reporter.warn(reporter_output, file_path, lineno)
                            else:
                                reporter.fail(reporter_output, file_path, lineno)
                    else:
                        reporter_output = ("Found web.conf [expose:] stanza without"
                                           " required `pattern=` property. Please"
                                           " add this required property. Stanza:"
                                           " [{}]. File: {}, Line: {}."
                                           ).format(section.name,
                                                    file_path,
                                                    section.lineno)
                        reporter.fail(reporter_output, file_path, section.lineno)
    else:
        reporter_output = "No web.conf file exists."
        reporter.not_applicable(reporter_output)
