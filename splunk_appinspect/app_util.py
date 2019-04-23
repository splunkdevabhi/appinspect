import os
import re

from splunk_appinspect.regex_matcher import RegexMatcher

def _is_path_outside_app_container(path, app_name, is_windows):
    ENVIRON = '$SPLUNK_HOME'
    ENVIRON_FOR_WINDOWS = '%SPLUNK_HOME%'
    if path.find(ENVIRON) >= 0:
        app_container = os.path.join(ENVIRON, 'etc', 'apps', app_name)
        if not path.startswith(app_container):
            return True
        else:
            return False
    else:
        if is_windows:
            if path.find(ENVIRON_FOR_WINDOWS) >= 0:
                app_container = os.path.join(ENVIRON_FOR_WINDOWS, 'etc', 'apps', app_name)
                if not path.startswith(app_container):
                    return True
                else:
                    return False
        return True

def is_manipulation_outside_of_app_container(path, app_name):
    ENVIRON = '$SPLUNK_HOME'
    ENVIRON_FOR_WINDOWS = '%SPLUNK_HOME%'
    if len(path) >= 2 and path[0] in ['\'', '"']:
        if path[0] == path[-1]:
            path = path[1:-1]
        else:
            #TODO MALFORM?
            pass
    if path.count(os.sep) > 0 or path.count('/'):
        if path.startswith(os.sep) or path.startswith('/'):
            return True
        else:
            np = os.path.normpath(path)
            # On Windows, splunk can recognize $SPLUNK_HOME and %SPLUNK_HOME%
            if os.name == 'nt':
                if re.match(r'([a-zA-Z]\:|\.)\\', np):
                    return True
                return _is_path_outside_app_container(np, app_name, True)
            else:
                return _is_path_outside_app_container(np, app_name, False)
    elif path.startswith('..'):
        return True
    return False


class AppVersionNumberMatcher(RegexMatcher):
    def __init__(self):
        version_number_regex_patterns = [
            r'^(?P<major>\d+)\.(?P<minor>\d+)\.?(?P<others>\w*)$',
            r'^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<revision>\d+)(?P<suffix>[0-9a-z]*)$',
        ]
        super(AppVersionNumberMatcher, self).__init__(version_number_regex_patterns)

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
