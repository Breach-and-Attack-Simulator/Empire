from __future__ import print_function

import base64
import pathlib
from builtins import object, str
from typing import Dict

import donut
import yaml

from empire.server.common import helpers
from empire.server.common.module_models import PydanticModule
from empire.server.utils import data_util
from empire.server.utils.module_util import handle_error_message


class Module(object):
    @staticmethod
    def generate(
        main_menu,
        module: PydanticModule,
        params: Dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):

        with open(f"{main_menu.directory['downloads']}{params['File']}", "rb") as data:
            assembly_data = data.read()
        base64_assembly = base64.b64encode(assembly_data).decode("utf-8")

        compiler = main_menu.loadedPlugins.get("csharpserver")
        if not compiler.status == "ON":
            return None, "csharpserver plugin not running"

        # Convert compiler.yaml to python dict
        compiler_dict: Dict = yaml.safe_load(module.compiler_yaml)
        # delete the 'Empire' key
        del compiler_dict[0]["Empire"]
        # convert back to yaml string
        compiler_yaml: str = yaml.dump(compiler_dict, sort_keys=False)

        file_name = compiler.do_send_message(
            compiler_yaml, module.name, confuse=main_menu.obfuscate
        )
        if file_name == "failed":
            return None, "module compile failed"

        script_file = (
            main_menu.installPath
            + "/csharp/Covenant/Data/Tasks/CSharp/Compiled/"
            + (params["DotNetVersion"]).lower()
            + "/"
            + file_name
            + ".compiled"
        )

        script_end = f",{base64_assembly}, {params['TypeName']}, {params['MethodName']}, {params['Parameters']}"
        return f"{script_file}|{script_end}", None
