# File: netskope_utilities.py
#
# Copyright 2018-2025 Netskope, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
import logging
import os
import re
import sys
from logging import handlers


class KennyLoggins:
    """Base Class for Logging"""

    __module__ = __name__

    def __init__(self, **kwargs):
        """Construct an instance of the Logging Object"""
        pass

    def get_logger(self, app_name=None, file_name="kenny_loggins", log_level=logging.INFO, version="unknown"):
        """Initialize Logger"""
        log_location = ("{}{}").format(os.path.sep, os.path.join("var", "log", "phantom", "apps", app_name))
        _log = logging.getLogger(f"{app_name}/{file_name}")
        _log.propogate = False
        _log.setLevel(log_level)
        formatter = logging.Formatter(
            f'%(asctime)s log_level=%(levelname)s pid=%(process)d tid=%(threadName)s              file="%(filename)s \
                " function="%(funcName)s" line_number="%(lineno)d" version="{version}" %(message)s'
        )
        try:
            try:
                if not os.path.isdir(log_location):
                    os.makedirs(log_location)
                output_file_name = os.path.join(log_location, (f"{file_name}.log"))
                f_handle = handlers.RotatingFileHandler(output_file_name, maxBytes=25000000, backupCount=5)
                f_handle.setFormatter(formatter)
                if not len(_log.handlers):
                    _log.addHandler(f_handle)
            except Exception as e:
                handler = logging.StreamHandler(sys.stdout)
                handler.setLevel(log_level)
                handler.setFormatter(formatter)
                if not len(_log.handlers):
                    _log.addHandler(handler)
                _log.error(f"Failed to create file-based logging. {e}")

        finally:
            return _log


class netskope_utils:
    """Basic util class"""

    def __init__(self):
        """Construct an instance of the basic utils class"""
        kl = KennyLoggins()
        self._log = kl.get_logger(app_name="netskope_utils", file_name="netskope_utils")

    def _check_single_validation(self, validation_item, string):
        self._log.info(f"check_single validation_item={validation_item} string={string}")
        pattern = re.compile(validation_item.get("regex", ".*"))
        does_not_match = True if validation_item.get("op", "does_not_match") == "does_not_match" else False
        found_match = pattern.search(string)
        if (found_match is None and does_not_match) or (found_match is not None and not does_not_match):
            return validation_item.get("message", ("Failed regex: {}").format(validation_item.get("regex", ".*")))
        else:
            return False

    def _validate_configuration(self, item, item_config, key):
        self._log.info(f"validating_config item={item} item_config={item_config} key={key}")
        if "validation" not in item_config:
            return False
        si = [(f"{key}: {x}") for x in [self._check_single_validation(x, item) for x in item_config.get("validation")] if x]
        if len(si) < 1:
            return False
        return (", ").join(si)

    def validate_app_configuration(self, ac, config):
        """Validate app configuration"""
        return [self._validate_configuration(config.get(x, ""), ac[x], x) for x in ac]
