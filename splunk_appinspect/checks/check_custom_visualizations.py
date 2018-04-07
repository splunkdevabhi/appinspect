# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Custom Visualizations Support Checks

[Custom Visualizations](https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/CustomVizApiRef) are defined in `default/visualizations.conf`.
"""

# Python Standard Library
import logging
import os
import re
import urllib
# Third-Party Support
# N/A
# Custom
# N/A
import bs4

import splunk_appinspect
import struct
from splunk_appinspect.image_resource import ImageResource
from splunk_appinspect.custom_visualizations import CustomVisualizations, CustomVisualization

logger = logging.getLogger(__name__)

@splunk_appinspect.tags("splunk_appinspect", "custom_visualizations")
@splunk_appinspect.cert_version(min="1.5.0")
def check_for_visualizations_preview_png(app, reporter):
    """Check the required file `appserver/static/visualizations/<viz_name>/preview.png`
    exists for the visualization
    """
    if app.file_exists("default", "visualizations.conf"):
        custom_visualizations_component = app.get_custom_visualizations()
        if custom_visualizations_component.does_visualizations_directory_exist():
            for mod_viz in custom_visualizations_component.get_custom_visualizations():
                _check_preview_png_for_mod_viz(reporter, app, mod_viz)
        else:
            visualizations_folder_not_exist_message = "The `{}` directory does not exist."\
                                                            .format(CustomVisualizations.visualizations_directory())
            reporter.fail(visualizations_folder_not_exist_message)
    else:
        reporter_output = "visualizations.conf does not exist."
        reporter.not_applicable(reporter_output)


def _check_preview_png_for_mod_viz(reporter, app, mod_viz):
    visualization_dir = mod_viz.visualization_directory()
    if not mod_viz.does_visualization_directory_exist():
        vis_dir_not_exist_message = "The directory {} doesn't exist for this visualization {}" \
            .format(visualization_dir, mod_viz.name)
        reporter.fail(vis_dir_not_exist_message)
    else:
        if not mod_viz.does_preview_png_exist():
            preview_file_not_exist_message = "The required preview.png file doesn't exist " \
                                             "under folder {} for visualization {}" \
                .format(visualization_dir, mod_viz.name)
            reporter.fail(preview_file_not_exist_message)
        else:
            absolute_png_file_path = app.get_filename(mod_viz.preview_png_file_path())
            _check_png_dimension(reporter, visualization_dir, absolute_png_file_path)


def _check_png_dimension(reporter, visualization_dir, preview_png_path):
    try:
        preview_png_resource = ImageResource(preview_png_path)
        if not preview_png_resource.is_png():
            invalid_png_message = "The preview.png file under folder {} doesn't " \
                                  "appear to be a valid png file, and its content type is {}"\
                                    .format(visualization_dir, preview_png_resource.content_type())
            reporter.fail(invalid_png_message)
        else:
            image_dimension = preview_png_resource.dimensions()
            expected_dimension = CustomVisualization.valid_preview_png_dimensions()
            if not image_dimension == expected_dimension:
                invalid_preview_png_size_message = \
                    "The preview.png image dimension is {}x{}, " \
                    "however, {}x{} is expected" \
                    .format(image_dimension[0], image_dimension[1],
                            expected_dimension[0], expected_dimension[1])
                reporter.fail(invalid_preview_png_size_message)
    except NotImplementedError:
        invalid_png_message = "The preview.png file under folder {} doesn't " \
                              "appear to be a valid png file".format(visualization_dir)
        reporter.fail(invalid_png_message)


@splunk_appinspect.tags("splunk_appinspect", "custom_visualizations")
@splunk_appinspect.cert_version(min="1.1.18")
def check_for_visualizations_directory(app, reporter):
    """Check that custom visualizations have an
    `appserver/static/visualizations/` directory.
    """
    if app.file_exists("default", "visualizations.conf"):
        custom_visualizations_component = app.get_custom_visualizations()
        if custom_visualizations_component.does_visualizations_directory_exist():
            pass  # Success, Directory exists
        else:
            reporter_output = ("The `{}`"
                               " directory does not exist."
                               ).format(CustomVisualizations.visualizations_directory())
            reporter.fail(reporter_output)
    else:
        reporter_output = "visualizations.conf does not exist."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "developer_guidance", "custom_visualizations")
@splunk_appinspect.cert_version(min="1.1.18")
def check_that_visualizations_conf_has_matching_default_meta_stanza(app, reporter):
    """Check that each stanza in `default/vizualizations.conf` has a matching
    stanza in metadata/default.meta`.
    """
    if app.file_exists("default", "visualizations.conf"):
        custom_visualizations = app.get_custom_visualizations()
        if app.file_exists("metadata", "default.meta"):
            default_meta = app.get_meta("default.meta")

            visualizations_conf_stanza_names = [custom_visualization.name
                                                for custom_visualization
                                                in custom_visualizations.get_custom_visualizations()]
            default_meta_stanza_names = [stanza_name
                                         for stanza_name
                                         in default_meta.section_names()]

            for visualizations_conf_stanza_name in visualizations_conf_stanza_names:
                expected_default_meta_stanza_name = ("visualizations/{}"
                                                     ).format(visualizations_conf_stanza_name)
                if expected_default_meta_stanza_name not in default_meta_stanza_names:
                    reporter_output = ("No [{}] stanza found in default.meta"
                                       ).format(expected_default_meta_stanza_name)
                    reporter.warn(reporter_output)
        else:
            stanza_names = [custom_visualization.name
                            for custom_visualization
                            in custom_visualizations.get_custom_visualizations()]
            for stanza_name in stanza_names:
                reporter_output = ("visualizatsions.conf was detected, but no"
                                   " default.meta file was detected. Please add"
                                   " a default.meta file with the stanza [{}]"
                                   " declared and the desired permissions set."
                                   ).format(stanza_names)
                reporter.warn(reporter_output)
    else:
        reporter_output = "visualizations.conf does not exist."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "custom_visualizations")
@splunk_appinspect.cert_version(min="1.1.20")
def check_for_matching_stanza_visualization_directory(app, reporter):
    """Check that each custom visualization stanza in
    `default/visualizations.conf` has a matching directory in the
    `appserver/static/visualizations/` directory.
    """
    if app.file_exists("default", "visualizations.conf"):
        custom_visualizations = app.get_custom_visualizations()
        if custom_visualizations.does_visualizations_directory_exist():
            visualizations_without_directory = [custom_visualization
                                                for custom_visualization
                                                in custom_visualizations.get_custom_visualizations()
                                                if not custom_visualization.does_visualization_directory_exist()]
            for visualization_without_directory in visualizations_without_directory:
                reporter_output = ("The stanza [{}] is missing its corresponding"
                                   " directory at `{}`. Please add the"
                                   " visualization directory and its corresponding"
                                   " files."
                                   ).format(visualization_without_directory.name,
                                            visualization_without_directory.visualization_directory())
                reporter.fail(reporter_output)
        else:
            reporter_output = ("The `{}`"
                               " directory does not exist."
                               ).format(CustomVisualizations.visualizations_directory())
            reporter.fail(reporter_output)
    else:
        reporter_output = "visualizations.conf does not exist."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "custom_visualizations")
@splunk_appinspect.cert_version(min="1.5.0")
def check_for_required_files_for_visualization(app, reporter):
    """Check that each custom visualization stanza in
    `default/visualizations.conf` has some required source files in the
    `appserver/static/visualizations/<visualization_name>/` directory.
    """
    if app.file_exists("default", "visualizations.conf"):
        custom_visualizations = app.get_custom_visualizations()
        if custom_visualizations.does_visualizations_directory_exist():
            visualizations_with_directory = [custom_visualization
                                             for custom_visualization
                                             in custom_visualizations.get_custom_visualizations()
                                             if app.directory_exists(CustomVisualizations.visualizations_directory(),
                                                                     custom_visualization.name)]
            for visualization in visualizations_with_directory:
                missing_files = [source_file
                                 for source_file in custom_visualizations.visualization_required_files
                                 if not app.file_exists(CustomVisualizations.visualizations_directory(),
                                                        visualization.name, source_file)]
                for missing_file in missing_files:
                    reporter_output = ("Required custom visualization file not found: appserver/static/visualizations/{}/{}"
                                      ).format(visualization.name, missing_file)
                    reporter.fail(reporter_output)
        else:
            reporter_output = ("The `{}`"
                               " directory does not exist."
                               ).format(CustomVisualizations.visualizations_directory())
            reporter.fail(reporter_output)
    else:
        reporter_output = "visualizations.conf does not exist."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "custom_visualizations")
@splunk_appinspect.cert_version(min="1.5.0")
def check_for_formatter_html_comments(app, reporter):
    """Check `appserver/static/visualizations/<viz_name>/formatter.html` for comments that
    are removed by Splunk's `.../search_mrsparkle/exposed/js/util/htmlcleaner.js` when rendered.
    """
    if app.file_exists("default", "visualizations.conf"):
        custom_visualizations = app.get_custom_visualizations()
        if custom_visualizations.does_visualizations_directory_exist():
            visualizations_with_formatter_html = [custom_visualization
                                                  for custom_visualization
                                                  in custom_visualizations.get_custom_visualizations()
                                                  if app.file_exists(custom_visualizations.visualizations_directory(),
                                                                     custom_visualization.name,
                                                                     "formatter.html")]
            for visualization in visualizations_with_formatter_html:
                formatter_html_relative_path = os.path.join(custom_visualizations.visualizations_directory(),
                                                            visualization.name,
                                                            "formatter.html")
                formatter_html_full_path = os.path.join(app.app_dir,
                                                        custom_visualizations.visualizations_directory(),
                                                        visualization.name,
                                                        "formatter.html")
                with open(formatter_html_full_path) as f:
                    content = f.read()
                    content = "<div>" + content + "</div>"
                soup = bs4.BeautifulSoup(content, "lxml-xml")
                # find all comments
                comments = soup.find_all(string=lambda text: isinstance(text, bs4.Comment))
                for comment in comments:
                    comment_content = "<!--" + comment + "-->"
                    reporter_output = ("A custom visualization html file was found with html that"
                                       " has comments that are removed during Splunk run-time."
                                       " Please consider removing the comments."
                                       " file:{} comment:{}"
                                       ).format(formatter_html_relative_path, comment_content)
                    reporter.warn(reporter_output)
        else:
            reporter_output = ("The `{}`"
                               " directory does not exist."
                               ).format(custom_visualizations.visualizations_directory)
            reporter.fail(reporter_output)
    else:
        reporter_output = "visualizations.conf does not exist."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "custom_visualizations")
@splunk_appinspect.cert_version(min="1.5.0")
def check_for_formatter_html_bad_nodes(app, reporter):
    """Check `appserver/static/visualizations/<viz_name>/formatter.html` for bad nodes that
    are removed by Splunk's `.../search_mrsparkle/exposed/js/util/htmlcleaner.js` when rendered.
    """
    if app.file_exists("default", "visualizations.conf"):
        custom_visualizations = app.get_custom_visualizations()
        if custom_visualizations.does_visualizations_directory_exist():
            visualizations_with_formatter_html = [custom_visualization
                                                  for custom_visualization
                                                  in custom_visualizations.get_custom_visualizations()
                                                  if app.file_exists(custom_visualizations.visualizations_directory(),
                                                                     custom_visualization.name,
                                                                     "formatter.html")]
            for visualization in visualizations_with_formatter_html:
                formatter_html_relative_path = os.path.join(custom_visualizations.visualizations_directory(),
                                                            visualization.name,
                                                            "formatter.html")
                formatter_html_full_path = os.path.join(app.app_dir,
                                                        custom_visualizations.visualizations_directory(),
                                                        visualization.name,
                                                        "formatter.html")
                with open(formatter_html_full_path) as f:
                    content = f.read()
                    content = "<div>" + content + "</div>"
                soup = bs4.BeautifulSoup(content, "lxml-xml")

                reporter_output_pattern = ("A custom visualization html file was found with html that"
                                           " has tags that are removed during Splunk run-time."
                                           " Please consider removing the tags."
                                           " file:{} tag:{}")

                for tag_name in ["script", "link", "meta", "head"]:
                    for tag in soup.find_all(tag_name):
                        reporter_output = reporter_output_pattern.format(formatter_html_relative_path, tag.prettify())
                        reporter.warn(reporter_output)

                for tag in soup.find_all(type="text/javascript"):
                    reporter_output = reporter_output_pattern.format(formatter_html_relative_path, tag.prettify())
                    reporter.warn(reporter_output)
        else:
            reporter_output = ("The `{}`"
                               " directory does not exist."
                               ).format(custom_visualizations.visualizations_directory)
            reporter.fail(reporter_output)
    else:
        reporter_output = "visualizations.conf does not exist."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "custom_visualizations")
@splunk_appinspect.cert_version(min="1.5.0")
def check_for_formatter_html_inappropriate_attributes(app, reporter):
    """Check `appserver/static/visualizations/<viz_name>/formatter.html` for inappropriate attributes that
    are removed by Splunk's `.../search_mrsparkle/exposed/js/util/htmlcleaner.js` when rendered.
    """
    url_attributes = {
        "link": ["href"],
        "applet": ["code", "object"],
        "iframe": ["src"],
        "img": ["src"],
        "embed": ["src"],
        "layer": ["src"],
        "a": ["href"]
    }

    if app.file_exists("default", "visualizations.conf"):
        custom_visualizations = app.get_custom_visualizations()
        if custom_visualizations.does_visualizations_directory_exist():
            visualizations_with_formatter_html = [custom_visualization
                                                  for custom_visualization
                                                  in custom_visualizations.get_custom_visualizations()
                                                  if app.file_exists(custom_visualizations.visualizations_directory(),
                                                                     custom_visualization.name,
                                                                     "formatter.html")]
            for visualization in visualizations_with_formatter_html:
                formatter_html_relative_path = os.path.join(custom_visualizations.visualizations_directory(),
                                                            visualization.name,
                                                            "formatter.html")
                formatter_html_full_path = os.path.join(app.app_dir,
                                                        custom_visualizations.visualizations_directory(),
                                                        visualization.name,
                                                        "formatter.html")
                with open(formatter_html_full_path) as f:
                    content = f.read()
                    content = "<div>" + content + "</div>"
                soup = bs4.BeautifulSoup(content, "lxml-xml")

                for tag in soup.find_all():
                    tag_name = tag.name.lower() if tag.name else "".lower()
                    for attr_name, attr_val in tag.attrs.iteritems():
                        attr_str = "{}=\"{}\"".format(attr_name, attr_val)
                        if attr_name.lower().find("on") == 0:
                            reporter_output = ("A custom visualization html file was found with html that"
                                               " has inappropriate attributes that are replaced"
                                               " during Splunk run-time. Please consider removing the attributes."
                                               " file:{} tag:{} attribute:{}"
                                               ).format(formatter_html_relative_path, tag.name, attr_str)
                            reporter.warn(reporter_output)
                        else:
                            url_attrs = url_attributes.get(tag_name)
                            if not url_attrs or attr_name.lower() not in url_attrs:
                                continue
                            if not _is_bad_url(attr_val):
                                continue

                            reporter_output = ("A custom visualization html file was found with html that"
                                               " has inappropriate attributes that are removed"
                                               " during Splunk run-time. Please consider removing the attributes."
                                               " file:{} tag:{} attribute:{}"
                                               ).format(formatter_html_relative_path, tag.name, attr_str)
                            reporter.warn(reporter_output)
        else:
            reporter_output = ("The `{}`"
                               " directory does not exist."
                               ).format(custom_visualizations.visualizations_directory)
            reporter.fail(reporter_output)
    else:
        reporter_output = "visualizations.conf does not exist."
        reporter.not_applicable(reporter_output)


def _is_bad_url(url):
    return True if re.search("^(?:javascript|jscript|livescript|vbscript|data|about|mocha):",
                             _clean_url(url)) else False


def _clean_url(url):
    url = url if url else ""
    return re.sub("\s",
                  "",
                  urllib.unquote(url.strip()),
                  flags=re.MULTILINE | re.IGNORECASE)


@splunk_appinspect.tags("splunk_appinspect", "custom_visualizations")
@splunk_appinspect.cert_version(min="1.5.0")
def check_for_formatter_html_css_expressions(app, reporter):
    """Check `appserver/static/visualizations/<viz_name>/formatter.html` for css expressions from all <style> tags
    that are replaced by Splunk's `.../search_mrsparkle/exposed/js/util/htmlcleaner.js` when rendered.
    """
    if app.file_exists("default", "visualizations.conf"):
        custom_visualizations = app.get_custom_visualizations()
        if custom_visualizations.does_visualizations_directory_exist():
            visualizations_with_formatter_html = [custom_visualization
                                                  for custom_visualization
                                                  in custom_visualizations.get_custom_visualizations()
                                                  if app.file_exists(custom_visualizations.visualizations_directory(),
                                                                     custom_visualization.name,
                                                                     "formatter.html")]
            for visualization in visualizations_with_formatter_html:
                formatter_html_relative_path = os.path.join(custom_visualizations.visualizations_directory(),
                                                            visualization.name,
                                                            "formatter.html")
                formatter_html_full_path = os.path.join(app.app_dir,
                                                        custom_visualizations.visualizations_directory(),
                                                        visualization.name,
                                                        "formatter.html")
                with open(formatter_html_full_path) as f:
                    content = f.read()
                    content = "<div>" + content + "</div>"
                soup = bs4.BeautifulSoup(content, "lxml-xml")

                for style_tag in soup.find_all("style"):
                    new_text = re.sub("(^|[\s\W])expression(\s*\()",
                                      r"\1no-xpr\2",
                                      style_tag.string,
                                      flags=re.MULTILINE | re.IGNORECASE)
                    if new_text == style_tag.string:
                        continue

                    reporter_output = ("A custom visualization html file was found with html that"
                                       " has css expressions that are replaced during Splunk run-time."
                                       " Please consider removing the css expressions."
                                       " file: {} tag: {} css_expression: {}"
                                       ).format(formatter_html_relative_path, style_tag.name, style_tag.string)
                    reporter.warn(reporter_output)
        else:
            reporter_output = ("The `{}`"
                               " directory does not exist."
                               ).format(custom_visualizations.visualizations_directory)
            reporter.fail(reporter_output)
    else:
        reporter_output = "visualizations.conf does not exist."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "custom_visualizations")
@splunk_appinspect.cert_version(min="1.5.0")
def check_for_formatter_html_inline_style_attributes(app, reporter):
    """Check `appserver/static/visualizations/<viz_name>/formatter.html` for inline style attributes
    from all <style> tags that are removed by Splunk's `.../search_mrsparkle/exposed/js/util/htmlcleaner.js`
    when rendered.
    """
    if app.file_exists("default", "visualizations.conf"):
        custom_visualizations = app.get_custom_visualizations()
        if custom_visualizations.does_visualizations_directory_exist():
            visualizations_with_formatter_html = [custom_visualization
                                                  for custom_visualization
                                                  in custom_visualizations.get_custom_visualizations()
                                                  if app.file_exists(custom_visualizations.visualizations_directory(),
                                                                     custom_visualization.name,
                                                                     "formatter.html")]
            for visualization in visualizations_with_formatter_html:
                formatter_html_relative_path = os.path.join(custom_visualizations.visualizations_directory(),
                                                            visualization.name,
                                                            "formatter.html")
                formatter_html_full_path = os.path.join(app.app_dir,
                                                        custom_visualizations.visualizations_directory(),
                                                        visualization.name,
                                                        "formatter.html")
                with open(formatter_html_full_path) as f:
                    content = f.read()
                    content = "<div>" + content + "</div>"
                soup = bs4.BeautifulSoup(content, "lxml-xml")

                for style_tag in soup.find_all("style"):
                    if "style" not in style_tag.attrs:
                        continue
                    style_attr = "style=\"" + style_tag.attrs["style"] + "\""
                    reporter_output = ("A custom visualization html file was found with html that"
                                       " has inline style attributes for style tag that are removed"
                                       " during Splunk run-time. Please consider removing the css expressions."
                                       " file:{} tag:{} attribute:{}"
                                       ).format(formatter_html_relative_path, style_tag.name, style_attr)
                    reporter.warn(reporter_output)
        else:
            reporter_output = ("The `{}`"
                               " directory does not exist."
                               ).format(custom_visualizations.visualizations_directory)
            reporter.fail(reporter_output)
    else:
        reporter_output = "visualizations.conf does not exist."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "custom_visualizations")
@splunk_appinspect.cert_version(min="1.5.0")
def check_for_default_values_for_modviz(app, reporter):
    """check the property defined in spec file of `README/savedsearches.conf.spec`
    if the property is defined in spec file and does not provide a default value in
    `default/savedsearches.conf`, this check should fail.
    """
    if app.file_exists("default", "visualizations.conf"):
        custom_visualizations = app.get_custom_visualizations()
        if custom_visualizations.does_visualizations_directory_exist():
            custom_vizs = [viz for viz in custom_visualizations.get_custom_visualizations()
                                if app.directory_exists(custom_visualizations.visualizations_directory(),
                                viz.name)]
            if app.file_exists("README", "savedsearches.conf.spec"):
                spec_file = app.get_spec("savedsearches.conf.spec", dir="README")
                if not spec_file.has_section("default"):    # property is not defined in the default section of savedsearches.conf.spec
                    return
                spec_settings = spec_file.get_section("default").options.iteritems()
                modviz_options = [k for k, v in spec_settings if k.startswith("display.visualizations.custom.")]
                for viz in custom_vizs:
                    identify = "{app}.{viz}".format(app=custom_visualizations.app.name, viz=viz.name)
                    property_prefix = "display.visualizations.custom.{identify}.".format(identify=identify)
                    viz_option_spec = [k for k in modviz_options if k.startswith(property_prefix)]
                    if len(viz_option_spec) > 0:
                        config_file = app.get_config("savedsearches.conf")
                        if not config_file.has_section('default'):
                            reporter_output = "default stanza is not found in file: default/savedsearches.conf"
                            reporter.fail(reporter_output)
                        else:
                            default_section = config_file.get_section("default")
                            for key in viz_option_spec:
                                if not default_section.has_option(key):
                                    reporter_output = (
                                    "mod viz option {} should have a default value in default/savedsearches.conf".format(
                                        key))
                                    reporter.fail(reporter_output)