# -*- coding: utf8 -*-
# This file is part of PywerView.
# https://github.com/the-useless-one/pywerview/blob/master/pywerview/requester.py

# PywerView is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# PywerView is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with PywerView.  If not, see <http://www.gnu.org/licenses/>.

# Yannick Méheut [yannick (at) meheut (dot) org] - Copyright © 2016



import socket
import ntpath
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5 import transport, wkst, srvs, samr, scmr, drsuapi, epm
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.rpcrt import DCERPCException

class RPCRequester():
    def __init__(self, target_computer, domain=str(), user=(), password=str(),
                 lmhash=str(), nthash=str()):
        self._target_computer = target_computer
        self._domain = domain
        self._user = user
        self._password = password
        self._lmhash = lmhash
        self._nthash = nthash
        self._pipe = None
        self._rpc_connection = None
        self._dcom = None
        self._wmi_connection = None

    def _create_rpc_connection(self, pipe):
        # Here we build the DCE/RPC connection
        self._pipe = pipe

        binding_strings = dict()
        binding_strings['srvsvc'] = srvs.MSRPC_UUID_SRVS
        binding_strings['wkssvc'] = wkst.MSRPC_UUID_WKST
        binding_strings['samr'] = samr.MSRPC_UUID_SAMR
        binding_strings['svcctl'] = scmr.MSRPC_UUID_SCMR
        binding_strings['drsuapi'] = drsuapi.MSRPC_UUID_DRSUAPI

        # TODO: try to fallback to TCP/139 if tcp/445 is closed
        if self._pipe == r'\drsuapi':
            string_binding = epm.hept_map(self._target_computer, drsuapi.MSRPC_UUID_DRSUAPI,
                                          protocol='ncacn_ip_tcp')
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials(username=self._user, password=self._password,
                                         domain=self._domain, lmhash=self._lmhash,
                                         nthash=self._nthash)
        else:
            rpctransport = transport.SMBTransport(self._target_computer, 445, self._pipe,
                                                  username=self._user, password=self._password,
                                                  domain=self._domain, lmhash=self._lmhash,
                                                  nthash=self._nthash)

        rpctransport.set_connect_timeout(10)
        dce = rpctransport.get_dce_rpc()

        if self._pipe == r'\drsuapi':
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        try:
            dce.connect()
        except socket.error:
            self._rpc_connection = None
        else:
            dce.bind(binding_strings[self._pipe[1:]])
            self._rpc_connection = dce

    def _create_wmi_connection(self, namespace='root\\cimv2'):
        try:
            self._dcom = DCOMConnection(self._target_computer, self._user, self._password,
                                        self._domain, self._lmhash, self._nthash)
        except DCERPCException:
            self._dcom = None
        else:
            i_interface = self._dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                                        wmi.IID_IWbemLevel1Login)
            i_wbem_level1_login = wmi.IWbemLevel1Login(i_interface)
            self._wmi_connection = i_wbem_level1_login.NTLMLogin(ntpath.join('\\\\{}\\'.format(self._target_computer), namespace),
                                                                 NULL, NULL)

    @staticmethod
    def _rpc_connection_init(pipe=r'\srvsvc'):
        def decorator(f):
            def wrapper(*args, **kwargs):
                instance = args[0]
                if (not instance._rpc_connection) or (pipe != instance._pipe):
                    if instance._rpc_connection:
                        instance._rpc_connection.disconnect()
                    instance._create_rpc_connection(pipe=pipe)
                if instance._rpc_connection is None:
                    return None
                return f(*args, **kwargs)
            return wrapper
        return decorator

    @staticmethod
    def _wmi_connection_init():
        def decorator(f):
            def wrapper(*args, **kwargs):
                instance = args[0]
                if not instance._wmi_connection:
                    instance._create_wmi_connection()
                if instance._dcom is None:
                    return None
                return f(*args, **kwargs)
            return wrapper
        return decorator

    def __enter__(self):
        # Picked because it's the most used by the net* functions
        self._create_rpc_connection(r'\srvsvc')
        return self

    def __exit__(self, type, value, traceback):
        try:
            self._rpc_connection.disconnect()
        except AttributeError:
            pass
        self._rpc_connection = None
