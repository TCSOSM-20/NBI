#! /usr/bin/python3
# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__ = "Alfonso Tierno, alfonso.tiernosepulveda@telefonica.com"
__date__ = "2020-06-17"

import unittest
from unittest import TestCase
# from unittest.mock import Mock
# from osm_common import dbbase, fsbase, msgbase
from osm_nbi.base_topic import BaseTopic, EngineException


class Test_BaseTopic(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_name = "test-base-topic"

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass
        # self.db = Mock(dbbase.DbBase())
        # self.fs = Mock(fsbase.FsBase())
        # self.msg = Mock(msgbase.MsgBase())
        # self.auth = Mock(authconn.Authconn(None, None, None))

    def test_update_input_with_kwargs(self):

        test_set = (
            # (descriptor content, kwargs, expected descriptor (None=fails), message)
            ({"a": {"none": None}}, {"a.b.num": "v"}, {"a": {"none": None, "b": {"num": "v"}}}, "create dict"),
            ({"a": {"none": None}}, {"a.none.num": "v"}, {"a": {"none": {"num": "v"}}}, "create dict over none"),
            ({"a": {"b": {"num": 4}}}, {"a.b.num": "v"}, {"a": {"b": {"num": "v"}}}, "replace_number"),
            ({"a": {"b": {"num": 4}}}, {"a.b.num.c.d": "v"}, {"a": {"b": {"num": {"c": {"d": "v"}}}}},
             "create dict over number"),
            ({"a": {"b": {"num": 4}}}, {"a.b": "v"}, {"a": {"b": "v"}}, "replace dict with a string"),
            ({"a": {"b": {"num": 4}}}, {"a.b": None}, {"a": {}}, "replace dict with None"),
            ({"a": [{"b": {"num": 4}}]}, {"a.b.num": "v"}, None, "create dict over list should fail"),
            ({"a": [{"b": {"num": 4}}]}, {"a.0.b.num": "v"}, {"a": [{"b": {"num": "v"}}]}, "set list"),
            ({"a": [{"b": {"num": 4}}]}, {"a.3.b.num": "v"},
             {"a": [{"b": {"num": 4}}, None, None, {"b": {"num": "v"}}]}, "expand list"),
            ({"a": [[4]]}, {"a.0.0": "v"}, {"a": [["v"]]}, "set nested list"),
            ({"a": [[4]]}, {"a.0.2": "v"}, {"a": [[4, None, "v"]]}, "expand nested list"),
            ({"a": [[4]]}, {"a.2.2": "v"}, {"a": [[4], None, {"2": "v"}]}, "expand list and add number key"),
            ({"a": None}, {"b.c": "v"}, {"a": None, "b": {"c": "v"}}, "expand at root"),
        )
        for desc, kwargs, expected, message in test_set:
            if expected is None:
                self.assertRaises(EngineException, BaseTopic._update_input_with_kwargs, desc, kwargs)
            else:
                BaseTopic._update_input_with_kwargs(desc, kwargs)
                self.assertEqual(desc, expected, message)


if __name__ == '__main__':
    unittest.main()
