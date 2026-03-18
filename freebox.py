# Thanks to https://www.manatlan.com/blog/freeboxv6_api_v3_avec_python
# and https://github.com/supermat/PluginDomoticzFreebox
# Code under GPLv3
# AUTHOR : supermat & ilionel refork by fj
# CONTRIBUTOR : https://github.com/ilionel/PluginDomoticzFreebox/graphs/contributors
# Please not that supermat don't maintain this software anymore

"""
freebox.py is used by plugin.py
"""

import hashlib
import hmac
import json
import os
import re
import ssl
import time
import urllib.request
from urllib.request import urlopen, Request
from socket import timeout
from urllib.parse import urlparse
import Domoticz

# Globals CONSTANT
HOST = 'https://mafreebox.freebox.fr'
API_VER = '15'
TV_API_VER = '15'
REGISTER_TMOUT = 30
API_TMOUT = 4
CA_FILE = 'freebox_certificates.pem'


class FbxCnx:
    """
    FbxCnx describes methods to communicate with Freebox
    """

    def __init__(self, host=HOST, api=API_VER):
        self.host = host
        self.api_ver = int(float(api))
        self.requested_api_ver = int(float(api))
        self.api_base_url = '/api/'
        self.https_port = None
        self.api_domain = None
        self.info = None
        self.secure = ssl.create_default_context()

        cert_path = os.path.join(os.path.dirname(__file__), CA_FILE)
        request = Request(host + '/api_version')

        try:
            self.secure.load_verify_locations(cafile=cert_path)
            response = urlopen(request, timeout=API_TMOUT, context=self.secure).read()
            self.info = json.loads(response.decode())

            self.api_base_url = self.info.get('api_base_url', '/api/')
            self.https_port = int(self.info.get('https_port', 443))
            self.api_domain = self.info.get('api_domain', None)

            supported = int(float(self.info.get('api_version', self.api_ver)))
            self.api_ver = min(self.requested_api_ver, supported)

            Domoticz.Debug(f"Supported API version: {self.info['api_version']}")
            Domoticz.Debug(f"Freebox model: {self.info['box_model']}")

        except (urllib.error.HTTPError, urllib.error.URLError) as error:
            Domoticz.Error(f"Init error ('/api_version'): {error}")
            raise
        except timeout:
            Domoticz.Error('Timeout when call ("/api_version")')
            raise

        if self.info is None:
            Domoticz.Error('Fatal error: Unable to initialize Freebox connection!')
        elif int(float(self.info['api_version'])) < self.requested_api_ver:
            Domoticz.Error(
                f"You need to upgrade Freebox's firmware to use at least API version "
                f"{self.requested_api_ver} (current API version: {self.info['api_version']})."
            )

    def _request(self, path, method='GET', headers=None, data=None):
        """
        Send a request to Freebox API

        Args:
            path (str): api_url
            method (str, optional): method used for each request GET|POST|PUT. Defaults to 'GET'.
            headers (dict of str: str, optional): HTTP HEADERS. Defaults to None.
            data (dict of str: str, optional): POST or PUT datas. Defaults to None.

        Returns:
            (dict of str: str): Freebox API Response as dictionary
        """
        url = self._api_base() + path.lstrip('/')
        Domoticz.Debug('API REQUEST - URL: ' + url)
        Domoticz.Debug('API REQUEST - Method: ' + method)
        Domoticz.Debug('API REQUEST - Headers: ' + f"{headers}")
        Domoticz.Debug('API REQUEST - Data: ' + f"{data}")

        if data is not None:
            data = json.dumps(data).encode()

        request = Request(url=url, data=data, method=method)
        if headers is not None:
            request.headers.update(headers)

        api_response = urlopen(request, timeout=API_TMOUT, context=self.secure).read()
        Domoticz.Debug(f"<- API Response: {api_response}")
        dict_response = json.loads(api_response.decode())
        return dict_response

    def register(self, app_id, app_name, version, device_name, wait=REGISTER_TMOUT):
        """
        Register method is used to obtain a "app_token"

        Returns:
            str: "app_token" if success else empty string
        """
        data = {
            'app_id': app_id,
            'app_name': app_name,
            'app_version': version,
            'device_name': device_name
        }
        response = self._request('login/authorize/', 'POST', None, data)
        status = 'pending'
        if not response['success'] and response['msg']:
            Domoticz.Error(f"Registration error: {response['msg']}")
        else:
            track_id = response['result']['track_id']
            app_token = response['result']['app_token']
            while status != 'granted' and wait != 0:
                status = self._request(f"login/authorize/{track_id}")
                status = status['result']['status']
                wait = wait - 1
                time.sleep(1)
            if status == 'granted':
                return app_token
        return ""

    def _mksession(self, app_id, app_token):
        """
        Create a new authenticated session
        """
        challenge = self._request('login/')['result']['challenge']
        Domoticz.Debug('Challenge: ' + challenge)
        data = {
            "app_id": app_id,
            "password": hmac.new(app_token.encode(), challenge.encode(), hashlib.sha1).hexdigest()
        }
        session_token = self._request('login/session/', 'POST', None, data)['result']['session_token']
        Domoticz.Debug('Session Token: ' + session_token)
        return session_token

    def _disconnect(self, session_token):
        """
        Closing the current session
        """
        result = self._request(
            'login/logout/',
            'POST',
            {'Content-Type': 'application/json', 'X-Fbx-App-Auth': session_token}
        )
        Domoticz.Debug(f"Disconnect: {result}")
        return result

    def _api_base(self):
        """
        Construit la base d'URL API à partir de /api_version.
        Exemple attendu:
          https://<api_domain>:<https_port><api_base_url>v<api_ver>/
        """
        parsed = urlparse(self.host if '://' in self.host else ('https://' + self.host))
        scheme = parsed.scheme or 'https'
        hostname = self.api_domain if self.api_domain else (parsed.hostname or parsed.netloc or self.host)
        port = self.https_port if self.https_port else (parsed.port or 443)

        api_base = self.api_base_url or '/api/'
        if not api_base.startswith('/'):
            api_base = '/' + api_base
        api_base = api_base.rstrip('/') + '/'

        return f"{scheme}://{hostname}:{port}{api_base}v{self.api_ver}/"


class FbxApp(FbxCnx):
    """
    FbxApp describe methodes to call specified Freebox API
    """
    tv_player = None

    def __init__(self, app_id, app_token, host=HOST, session_token=None, enable_players=True):
        super().__init__(host)
        self.app_id = app_id
        self.app_token = app_token
        self.session_token = self._mksession(app_id, app_token) if session_token is None else session_token
        self.system = self.create_system()
        self.players = None
        if enable_players:
            self.create_players()

    def __del__(self):
        try:
            session_token = getattr(self, 'session_token', None)
            if session_token:
                self._disconnect(session_token)
        except Exception:
            pass

    def post(self, path, data=None):
        return self._request(path, 'POST', {"X-Fbx-App-Auth": self.session_token}, data)

    def put(self, path, data=None):
        return self._request(path, 'PUT', {"X-Fbx-App-Auth": self.session_token}, data)

    def get(self, path):
        return self._request(path, 'GET', {"X-Fbx-App-Auth": self.session_token})

    def call(self, path):
        result = {}
        try:
            api_result = self.get(path)
            if api_result['success'] and 'result' in api_result:
                result = api_result['result']
        except (urllib.error.HTTPError, urllib.error.URLError) as error:
            Domoticz.Error(f"API Error ('{path}'): {error}")
        except timeout:
            Domoticz.Error(f"Timeout when call ('{path}')")
        return result

    def percent(self, value, total, around=2):
        percent = 0
        if total > 0:
            percent = value / total * 100
        return round(percent, around)

    def ls_devices(self):
        return self.call('lan/browser/pub/')

    def ls_storage(self):
        result = {}
        ls_disk = self.call('storage/disk/')
        for disk in ls_disk:
            if 'partitions' not in disk:
                continue
            for partition in disk['partitions']:
                label = partition['label']
                used = partition['used_bytes']
                total = partition['total_bytes']
                percent = self.percent(used, total)
                Domoticz.Debug(f"Usage of disk '{label}': {used}/{total} bytes ({percent}%)")
                result.update({str(label): str(percent)})
        return result

    def get_name_from_macaddress(self, p_macaddress):
        result = None
        ls_devices = self.ls_devices()
        for device in ls_devices:
            macaddress = device['id']
            if ("ETHER-" + p_macaddress.upper()) == macaddress.upper():
                result = device['primary_name']
        return result

    def reachable_macaddress(self, p_macaddress):
        result = False
        ls_devices = self.ls_devices()
        for device in ls_devices:
            macaddress = device['id']
            if ("ETHER-" + p_macaddress.upper()) == macaddress.upper():
                reachable = device['reachable']
                if reachable:
                    result = True
                    break
        return result

    def online_devices(self):
        result = {}
        ls_devices = self.ls_devices()
        for device in ls_devices:
            name = device['primary_name']
            reachable = device['reachable']
            macaddress = device['id']
            if reachable:
                result.update({macaddress: name})
        return result

    def alarminfo(self):
        result = {}
        prerequisite_pattern = '^fbxgw7-r[0-9]+/full$'
        if self.info is None or re.match(prerequisite_pattern, self.info['box_model']) is None:
            return result

        nodes = self.call('home/tileset/all')
        for node in nodes:
            device = {}
            label = ''
            if node["type"] == "alarm_control":
                device.update({"type": str(node["type"])})
                for data in node["data"]:
                    if (data["ep_id"] == 11) and node["type"] == "alarm_control":
                        label = data["label"]
                        if data['value'] == 'alarm1_armed':
                            value = 1
                            device.update({"alarm1_status": str(value)})
                        elif data['value'] == 'alarm1_arming':
                            value = -1
                            device.update({"alarm1_status": str(value)})
                        else:
                            value = 0
                            device.update({"alarm1_status": str(value)})

                        if data['value'] == 'alarm2_armed':
                            value = 1
                            device.update({"alarm2_status": str(value)})
                        elif data['value'] == 'alarm2_arming':
                            value = -1
                            device.update({"alarm2_status": str(value)})
                        else:
                            value = 0
                            device.update({"alarm2_status": str(value)})
                        device.update({"label": str(label)})
                    elif (data["ep_id"] == 13) and node["type"] == "alarm_control":
                        status_error = data["value"]
                        device.update({"status_error": str(status_error)})
                    elif data["name"] == 'battery_warning':
                        battery = data["value"]
                        device.update({"battery": str(battery)})

                    device1 = device.copy()
                    device2 = device.copy()
                    if 'alarm1_status' in device1:
                        device1['value'] = device1['alarm1_status']
                        device1['label'] = device1['label'] + '1'
                    if 'alarm2_status' in device2:
                        device2['value'] = device2['alarm2_status']
                        device2['label'] = device2['label'] + '2'
                    result.update({device1['label']: device1})
                    result.update({device2['label']: device2})

        nodes = self.call("home/nodes")
        for node in nodes:
            device = {}
            label = ''
            if (node["category"] == "pir") or (node["category"] == "dws"):
                label = node["label"]
                device.update({"label": str(label)})
                device.update({"type": str(node["category"])})
                for endpoint in node["show_endpoints"]:
                    if endpoint["name"] == 'battery':
                        battery = endpoint["value"]
                        device.update({"battery": str(battery)})
                    elif endpoint["name"] == 'trigger':
                        if endpoint["value"]:
                            device.update({"value": 0})
                        elif not endpoint["value"]:
                            device.update({"value": 1})
                result.update({label: device})
        return result

    def connection_rate(self):
        result = {}
        connection = self.call('connection/')
        if not connection:
            return result
        if 'rate_down' in connection and connection['rate_down'] is not None:
            result.update({str('rate_down'): str(connection['rate_down'] / 1024)})
        if 'rate_up' in connection and connection['rate_up'] is not None:
            result.update({str('rate_up'): str(connection['rate_up'] / 1024)})
        return result

    def wan_state(self):
        state = None
        connection = self.call('connection/')
        if not connection:
            return False
        if connection.get('state') == 'up':
            Domoticz.Debug('Connection is UP')
            state = True
        else:
            Domoticz.Debug('Connection is DOWN')
            state = False
        return state

    def wifi_state(self):
        wifi = self.call('wifi/config/')
        enabled = wifi.get('enabled') if isinstance(wifi, dict) else None
        if enabled is None:
            Domoticz.Error("Wifi state unavailable (missing 'enabled')")
            return None
        Domoticz.Debug('Wifi interface is UP' if enabled else 'Wifi interface is DOWN')
        return bool(enabled)

    def wifi_enable(self, switch_on):
        status = None
        data = {'enabled': bool(switch_on)}
        try:
            response = self.put("wifi/config/", data)
            status = False
            if response['success']:
                if response['result']['enabled']:
                    status = True
                    Domoticz.Debug('Wifi is now ON')
                else:
                    Domoticz.Debug('Wifi is now OFF')
        except (urllib.error.HTTPError, urllib.error.URLError) as error:
            Domoticz.Error(f"API Error ('wifi/config/'): {error}")
        except timeout as exc:
            if not switch_on:
                Domoticz.Error('Wifi disabled')
                status = False
            else:
                raise timeout from exc
        return status

    def reboot(self):
        Domoticz.Debug('Try to reboot with session : ' + self.session_token)
        response = self.post("system/reboot")
        if response['success']:
            Domoticz.Debug('Reboot initiated')
        else:
            Domoticz.Error('Error: You must grant reboot permission')

    def next_pvr_precord_timestamp(self, relative=True):
        precord = False
        now = int(time.time())
        next_recording = now - 1
        result = self.call('/pvr/programmed')
        Domoticz.Debug(f"PVR Programmed List: {result}")
        for pvr in result:
            if pvr['state'] == 'waiting_start_time':
                recording_start = int(float(pvr['start']))
                if not precord:
                    next_recording = recording_start
                    precord = True
                next_recording = recording_start if recording_start < next_recording else next_recording
            elif pvr['state'] in ('starting', 'running', 'running_error'):
                next_recording = now
                break
        return (next_recording - now) if relative else next_recording

    def create_system(self):
        self.system = FbxApp.System(self)
        return self.system

    def create_players(self):
        self.players = FbxApp.Players(self)
        return self.players

    class System:
        def __init__(self, fbxapp):
            self.server = fbxapp
            self.info = self.getinfo()

        def getinfo(self):
            result = self.server.call('/system')
            Domoticz.Debug(f"Freebox Server Infos: {result}")
            return result

        def sensors(self):
            result = {}
            if self.info and "sensors" in self.info and self.info["sensors"]:
                result = self.info["sensors"]
            return result

    class Players:
        def __init__(self, fbxapp):
            self.server = fbxapp
            self.info = self.getinfo()

        def getinfo(self):
            result = self.server.call('/player')
            if result:
                self.server.tv_player = True
                Domoticz.Debug('Player(s) are registered on the local network')
                Domoticz.Debug(f"Player(s) Infos: {result}")
            else:
                self.server.tv_player = False
                Domoticz.Error('Error: You must grant Player Control permission')
            return result

        def ls_uid(self):
            result = []
            players = self.info
            for player in players:
                result.append(player['id'])
                Domoticz.Debug(f"Player(s) Id: {result}")
            return result

        def state(self, uid):
            status = None
            try:
                response = self.server.get(f"/player/{uid}/api/v{TV_API_VER}/status")
            except urllib.error.HTTPError as error:
                if error.code == 504:
                    status = False
                else:
                    Domoticz.Error(f"API Error ('/player/{uid}/api/v{TV_API_VER}/status'): {error}")
            except urllib.error.URLError as error:
                Domoticz.Error(f"API Error ('/player/{uid}/api/v{TV_API_VER}/status'): {error}")
            except timeout:
                Domoticz.Error('Timeout')
            else:
                if response['success'] and response['result']['power_state']:
                    status = True if response['result']['power_state'] == 'running' else False
            Domoticz.Debug(f"Is watching TV{uid}? : {status}")
            return status

        def remote(self, uid, remote_code, key, long=False):
            url = f"http://hd{uid}.freebox.fr/pub/remote_control?code={remote_code}&key={key}"
            if long:
                url = url + '&long=true'
            response = None
            try:
                request = Request(url)
                response = urlopen(request, timeout=API_TMOUT).read()
            except (urllib.error.HTTPError, urllib.error.URLError) as error:
                Domoticz.Error(f"TV Remote error ('{url}'): {error}")
            except timeout:
                Domoticz.Error('Timeout')
            return response

        def shutdown(self, uid, remote_code):
            return self.remote(uid, remote_code, "power")





