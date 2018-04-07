# Copyright 2017 Splunk Inc. All rights reserved.

"""
### Web.conf File Standards

Ensure that `default/web.conf` is safe for cloud deployment and that any exposed
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
    """Check that `default/web.conf` only defines [endpoint:*] and [expose:*]
    stanzas, with [expose:*] only containing `pattern=` and `methods=`."""
    if app.file_exists("default", "web.conf"):
        web_conf = app.web_conf()
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
                    reporter_output = ("Please verify that this custom Module"
                                       " System endpoint script complies"
                                       " with Splunk Cloud security policies."
                                       " Methods defined by this script should"
                                       " be available as web endpoints at:"
                                       " /custom/{}/{}/*. File: {}"
                                       .format(app.name, endpoint_name,
                                               script_path))
                    reporter.manual_check(reporter_output, script_path)
                else:
                    reporter_output = ("web.conf [endpoint:] defined but no"
                                       " corresponding Python script was found."
                                       " Please add a script to: {} or remove"
                                       " the [{}] stanza from web.conf."
                                       .format(script_path, section.name))
                    reporter.warn(reporter_output)
            elif section.name.startswith("expose:"):
                # [expose:*] stanzas are allowed
                # Fail all properties besides `pattern` and `methods`
                for key, value in section.options.iteritems():
                    if key != "pattern" and key != "methods":
                        reporter_output = ("Only the `pattern` and `methods`"
                                           " properties are permitted for"
                                           " [expose:*] stanzas. Please remove"
                                           " this property: `{}`. Stanza: [{}]."
                                           " File: default/web.conf"
                                           .format(key, section.name))
                        reporter.fail(reporter_output)
            else:
                # stanzas other than [endpoint:*] and [expose:*] are forbidden
                reporter_output = ("Only the [endpoint:*] and [expose:*]"
                                   " stanzas are permitted in web.conf for"
                                   " cloud. Please remove this stanza from"
                                   " web.conf: [{}]. File: default/web.conf"
                                   .format(section.name))
                reporter.fail(reporter_output)
    else:
        reporter_output = "No web.conf file exists."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.5.0")
@splunk_appinspect.display(report_display_order=6)
def check_web_conf_expose_patterns_have_restmap_matches(app, reporter):
    """Check that apps only expose web endpoints that are defined by
    the Splunk App within `default/restmap.conf`. Each `default/web.conf`
    [expose:*] stanza should have the property `pattern=` which defines a url
    pattern to expose. Each url pattern exposed should correspond to a stanza
    within `default/restmap.conf` with a url pattern defined with the `match=`
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

    if app.file_exists("default", "web.conf"):
        web_conf = app.web_conf()
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
                        if app.file_exists("default", "restmap.conf"):
                            unformatted_restmap_patterns = app.get_rest_map().all_restmap_patterns()
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
                        reporter_output = ("web.conf found with a `pattern`"
                                           " exposed that does not correspond"
                                           " to any `match` stanza in"
                                           " restmap.conf. Apps should only"
                                           " expose endpoints that they define."
                                           " Pattern: `{}`. Please remove/edit"
                                           " this stanza: [{}]. File:"
                                           " default/web.conf"
                                           .format(pattern_to_compare, section.name))
                        # Special case: the /data/* endpoint will be exposed
                        # whether or not the app includes it in web.conf and
                        # this is currently exposed in all Add-Ons created by
                        # Add-On builder so only WARN for this case
                        if pattern_to_compare.startswith("/data/"):
                            reporter.warn(reporter_output)
                        else:
                            reporter.fail(reporter_output)
                else:
                    reporter_output = ("web.conf [expose:] stanza found without"
                                       " required `pattern=` property. Please"
                                       " add this required property. Stanza:"
                                       " [{}]. File: default/web.conf"
                                       .format(section.name))
                    reporter.fail(reporter_output)
    else:
        reporter_output = "No web.conf file exists."
        reporter.not_applicable(reporter_output)
