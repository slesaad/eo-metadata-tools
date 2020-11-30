# NASA EO-Metadata-Tools Python interface for the Common Metadata Repository (CMR)
#
#     https://cmr.earthdata.nasa.gov/search/site/docs/search/api.html
#
# Copyright (c) 2020 United States Government as represented by the Administrator
# of the National Aeronautics and Space Administration. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

"""
Library for generating EDL tokens from CMR
date: 2020-10-26
since: 0.0
"""

from urllib import request
from http.cookiejar import CookieJar
import getpass
import netrc
import subprocess

import cmr.util.common as common

# ##############################################################################
# local utilities

SIT = "sit.urs.earthdata.nasa.gov"
UAT = "uat.urs.earthdata.nasa.gov"
OPS = "urs.earthdata.nasa.gov"

# ##############################################################################
# lambdas

# All password lambda functions accept two parameters and return a string
# Parameters:
#   user_id(string): Earth Data Login user name
#   options(dictionary): configuration object which may be used by the lambda
# Returns:
#   password

def password(user, clear_password):
    """
    Create a pass through lambda function to allow plain text passwords, not an
    encouraged act however. This was created to make testing easier
    Parameters:
        clear_password(string): password in clear text
    Returns:
        A lambda function with conforms to the definition
    """
    return lambda _ : (user, clear_password)

def password_netrc(options=None):
    """
    Retrieve the password from a .netrc file.

    Parameters:
        options(dictionary): Responds to the following
            edl.env = EDL login environment, defaults to OPS
            cmr.netrc.file = netrc file to load, defaults to library default (pass None)
    Returns:
        username, password from .netrc file
    """
    endpoint = common.dict_or_default(options, "edl.env", OPS)
    net_file = common.dict_or_default(options, "cmr.netrc.file", None)
    if net_file is None:
        username, _, pword = netrc.netrc().authenticators(endpoint)
    else:
        username, _, pword = netrc.netrc(net_file).authenticators(endpoint)
    return username, pword

def password_manager(options=None):
    """
    Use a system like the MacOS X Keychain app. Any os which also has the
    security app would also work.

    Parameters:
        options(dictionary): Responds to the following:
            'password.manager.account': account field in Keychain record (default to 'user')
            'password.manager.app': command to use (default to /usr/bin/security)
            'password.manager.service': where field in Keychain record (default to cmr-lib-password)
    Return:
        account, password From keychain
    """
    app = common.dict_or_default(options, "password.manager.app", "/usr/bin/security")
    account = common.dict_or_default(options, "password.manager.account", "user")
    service = common.dict_or_default(options, "password.manager.service", "cmr-lib-password")
    try:
        result = common.call_security(account, service, app)
    except subprocess.CalledProcessError:
        account = None
        result = None

    return account, result

def password_ask(options=None):
    """
    Ask the user to enter in their user name and password, used as a last resort

    Parameters:
        options(dictionary): Responds to the following:
            'edl.env': EarthData Login URL (default is OPS)
    Return:
        username, password from user input
    """
    endpoint = common.dict_or_default(options, "edl.env", OPS)
    print('Please provide your Earthdata Login credentials to allow data access')
    print('Your credentials will only be passed to %s and will not be exposed in Jupyter'
        % (endpoint))
    username = input('EDL user name:')
    pword = getpass.getpass()
    return username, pword

# ##############################################################################
# functions

def request_account(password_handler_list=None, options=None):
    """
    Recursively request passwords using the supplied list of handlers

    Parameters:
        password_handler_list: a list of lambdas in stack order
        options: Responds to nothing
    Returns:
        username, password
    """
    if password_handler_list is None:
        password_handler_list = [password_ask,password_netrc]
    if not isinstance(password_handler_list, list):
        password_handler_list = [password_handler_list]
    try:
        password_handler = password_handler_list.pop()
        username, pword = password_handler(options)
    except (FileNotFoundError, TypeError):
        # FileNotFound = There's no .netrc file
        # TypeError = The endpoint isn't in the netrc file, causing the above to try unpacking None
        username = None
        pword = None
    if username is None or pword is None:
        if len(password_handler_list) > 0:
            username, pword = request_account(password_handler_list, options)
    return username, pword

# not a testable function
def setup_earthdata_cookie(username, pword, options=None):
    """
    Setup a cookie jar and add the user name and password so that future
    requests will login using them

    Parameters:
        username(string):
        pword(string):
        options(dictionary): Responds to the following:
            'edl.env': EarthData Login URL (default is OPS)
    """
    endpoint = common.dict_or_default(options, "edl.env", OPS)
    manager = request.HTTPPasswordMgrWithDefaultRealm()
    manager.add_password(None, endpoint, username, pword)
    auth = request.HTTPBasicAuthHandler(manager)

    jar = CookieJar()
    processor = request.HTTPCookieProcessor(jar)
    opener = request.build_opener(auth, processor)
    request.install_opener(opener)

# not a testable function
def earthdata_login(password_handlers=None, options=None):
    """
    Set up the request library so that it authenticates against the given
    EarthData Login endpoint and is able to track cookies between requests. This
    looks in the .netrc file first and if no credentials are found, it prompts
    for them.

    Password handlers are lambdas which request a password from different
    sources. A list can be supplied and the API will search the list in stack
    order. The default is [password_ask, password_netrc] (netrc then ask).
    Currently there are four password lambdas:
        password(username, password) - used as a passthrough lambda, for hardcoding values
        password_netrc - request account info from a .netrc file
        password_manager - request account info from Mac OS X Keychain if available
        password_ask - request account info from a live carbon based human

    To write a password lambda, accept a dictionary and return a username and password

    Parameters:
        environment(string): overwrites EDL URL in options (default None which means use options)
        password_handlers: list of lambdas in stack order or a single lambda,
            (default is password_netrc followed by password_ask)
        options: Responds to the following:
            'edl.env': EarthData Login URL (default is OPS)
    """
    username, pword = request_account(password_handlers)
    setup_earthdata_cookie(username, pword, options)

def setup_earthdata_login_auth(environment=None):
    """
    Set up the request library so that it authenticates against the given
    EarthData Login endpoint and is able to track cookies between requests. This
    looks in the .netrc file first and if no credentials are found, it prompts
    for them.

    Valid endpoints include:
        uat.urs.earthdata.nasa.gov - Earthdata Login UAT (Harmony's current default)
        urs.earthdata.nasa.gov - Earthdata Login production

    Parameters:
        environment(string): EDL URL (default None which means production)
     """
    options = {}
    if environment is not None:
        options["edl.env"] = environment
    earthdata_login([password_ask,password_netrc], options)

def print_help(prefix=""):
    """
    Built in help - returns the public functions and descriptions
    Parameters:
        filter(string): filters out functions beginning with this text, defaults to all
    """
    formater = common.help_format_lambda(prefix)

    output = ("**** Functions:")
    output += formater("print_help()", print_help)
    output += formater("setup_earthdata_login_auth(environment, options)",
        setup_earthdata_login_auth)
    output += "**** Password Lambdas:"
    output += formater("password(clear-text)", password)
    output += formater("password_netrc", password_netrc)
    output += formater("password_ask", password_ask)
    output += formater("password_manager", password_manager)
    return output
