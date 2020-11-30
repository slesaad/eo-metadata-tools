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
Test cases for the cmr.auth package
date 2020-10-15
since 0.0
"""

from unittest.mock import patch
import unittest

import test.cmr as util
import cmr.auth.login as login
import cmr.util.common as common

# ******************************************************************************

class TestToken(unittest.TestCase):
    """ Test suit for cmr.auth.token """

    # **********************************************************************
    # Tests
    def test_password(self):
        """Test the password pass through function"""
        pass_func = login.password("User", "Test-Value")
        self.assertEqual(("User", "Test-Value"), pass_func(None))
        self.assertEqual(("User", "Test-Value"), pass_func({}))
        self.assertEqual(("User", "Test-Value"), pass_func({"key":"value"}))

    def test_password_netrc(self):
        """Test the netrc lookup by creating a file and testing against it"""
        #setup
        netrc_file = "/tmp/__test_netrc_file__.txt"
        util.delete_file(netrc_file)
        expected_content = "machine localhost login EDLUser password Secrete\n"
        expected_content += "machine remotehost.com login OtherAccount password Private\n"
        common.write_file(netrc_file, expected_content)

        #test
        options = {"edl.env":"localhost", "cmr.netrc.file":netrc_file}
        self.assertEqual(("EDLUser","Secrete"), login.password_netrc(options))
        options["edl.env"] = "remotehost.com"
        self.assertEqual(("OtherAccount","Private"), login.password_netrc(options))

        #cleanup
        util.delete_file(netrc_file)

    @patch('cmr.util.common.execute_command')
    def test_password_manager(self, cmd_mock):
        """Test a valid login using the password manager"""
        expected = "Secure-Code"
        options = {}
        cmd_mock.return_value = expected
        self.assertEqual(('user', expected), login.password_manager(options))

    @patch('getpass.getpass')
    @patch('builtins.input')
    @patch('builtins.print')
    def test_password_ask(self, print_mock, input_mock, getpass_mock):
        """Check to function that asks the user for input"""
        input_mock.return_value = "User"
        getpass_mock.return_value = "Secure"
        print_mock.return_value = None  # suppress output
        self.assertEqual(("User","Secure"), login.password_ask({}))

    @patch('getpass.getpass')
    @patch('builtins.input')
    @patch('builtins.print')
    def test_request_account_two_ways(self, print_mock, input_mock, getpass_mock):
        """Test the connivence function that tries to get a password in two ways"""
        # pylint: disable=protected-access
        input_mock.return_value = "User"
        getpass_mock.return_value = "Typed"
        print_mock.return_value = None  # suppress output

        # make a request that we know will work
        self.assertEqual(("user", "clear-text"),
            login.request_account([login.password_ask,login.password("user", "clear-text")], {}))

        #make a request that will cause the primary to fail, needing the secondary to trigger
        options = {"edl.env":"localhost", "cmr.netrc.file":"/tmp/fake_file.text"}
        self.assertEqual(("User", "Typed"),
            login.request_account(options=options))

    def test_help_full(self):
        """Test the built in help"""
        result_full = login.print_help()
        self.assertTrue (-1<result_full.find("setup_earthdata_login_auth"))
        self.assertTrue (-1<result_full.find("password_ask"))

    def test_help_less(self):
        """Test the built in help for filtering"""
        result_less = login.print_help("password")
        self.assertFalse (-1<result_less.find("setup_earthdata_login_auth"))
        self.assertTrue (-1<result_less.find("password_ask"))
