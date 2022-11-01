# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import importlib
import json
import logging
import os
import shutil
import sys
import tempfile

from cloudinit import cloud, distros, helpers, util
from cloudinit.sources import DataSourceNone


class InspectorHandler(logging.StreamHandler):
    """
    A handler class to check log level of records.
    """
    has_warning = False
    has_error = False

    def emit(self, record):
        if record.levelno == logging.WARNING:
            self.has_warning = True
        if record.levelno >= logging.ERROR:
            self.has_error = True

    def reset(self):
        self.has_warning = False
        self.has_error = False


if len(sys.argv) == 3:
    DISTRO_NAME = sys.argv[1]
    MODULE_NAME = sys.argv[2]

    # Load module.
    module = importlib.import_module('cloudinit.config.' + MODULE_NAME)

    # Configure logging.
    stream_handler = logging.StreamHandler(stream=sys.stderr)
    inspector_handler = InspectorHandler()
    log = module.LOG if hasattr(
        module, 'LOG') else logging.getLogger(__name__)
    log.setLevel(logging.WARNING)
    log.addHandler(stream_handler)
    log.addHandler(inspector_handler)

    # Load config.
    sys_cfg = {}
    cfg = json.load(sys.stdin)

    # Create required paths.
    tmp_dir = tempfile.mkdtemp(
        prefix="ci-osconfig-{}-{}.".format(MODULE_NAME, __name__))
    templates_dir = os.path.normpath(os.path.abspath(
        os.path.join(tmp_dir , 'templates_dir')))
    run_dir = os.path.normpath(os.path.abspath(
        os.path.join(tmp_dir , 'run_dir')))
    cloud_dir = os.path.normpath(os.path.abspath(
        os.path.join(tmp_dir , 'cloud_dir')))
    cloud_data_dir = os.path.normpath(os.path.abspath(
        os.path.join(tmp_dir , 'cloud_dir', 'data')))
    util.ensure_dirs([templates_dir, run_dir, cloud_dir, cloud_data_dir])

    paths = helpers.Paths(
        {'templates_dir': templates_dir, 'run_dir': run_dir, 'cloud_dir': cloud_dir})

    # Load distro.
    distro_cls = distros.fetch(DISTRO_NAME)
    distro = distro_cls(DISTRO_NAME, sys_cfg, paths)

    # Create data source.
    data_source = DataSourceNone.DataSourceNone(sys_cfg, distro, paths)

    # Create cloud.
    cloud = cloud.Cloud(data_source, paths, sys_cfg, distro, None)

    # Run module.
    module.handle(MODULE_NAME, cfg, cloud, log, None)

    # Cleanup.
    if tmp_dir:
        shutil.rmtree(tmp_dir)

    if not inspector_handler or inspector_handler.has_warning or inspector_handler.has_error:
        raise SystemExit(1)
else:
    raise 'missing args'