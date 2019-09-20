#!/usr/bin/env python3

import http.server
import threading
import ssl
import os
import sys
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from gevent import sleep
from cmx.helpers.logger import highlight
from cmx.logger import CMXLogAdapter
from cmx import config as cfg


class RequestHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        server_logger = CMXLogAdapter(extra={'module': self.server.module.name.upper(), 'host': self.client_address[0]})
        server_logger.info("- - %s" % (format%args))

    def do_GET(self):
        if hasattr(self.server.module, 'on_request'):
            server_logger = CMXLogAdapter(extra={'module': self.server.module.name.upper(), 'host': self.client_address[0]})
            self.server.context.log = server_logger
            self.server.module.on_request(self.server.context, self)

    def do_POST(self):
        if hasattr(self.server.module, 'on_response'):
            server_logger = CMXLogAdapter(extra={'module': self.server.module.name.upper(), 'host': self.client_address[0]})
            self.server.context.log = server_logger
            self.server.module.on_response(self.server.context, self)

    def stop_tracking_host(self):
        '''
            This gets called when a module has finshed executing, removes the host from the connection tracker list
        '''

        try:
            self.server.hosts.remove(self.client_address[0])
            if hasattr(self.server.module, 'on_shutdown'):
                self.server.module.on_shutdown(self.server.context, self.server.connection)
        except ValueError:
            pass

class CMXServer(threading.Thread):

    def __init__(self, module, context, logger, srv_host, port, server_type='https'):

        try:
            threading.Thread.__init__(self)

            self.server = HTTPServer((srv_host, int(port)), RequestHandler)
            self.server.hosts   = []
            self.server.module  = module
            self.server.context = context
            self.server.log     = CMXLogAdapter(extra={'module': self.server.module.name.upper(), 'host': ''})  #blank host set for formatting reasons. without it we dont get the same logging setup
            self.cert_path      = cfg.CERT_PATH
            self.server.track_host = self.track_host

            logging.debug('CMX server type: ' + server_type)
            if server_type == 'https':
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                self.server.socket = ssl.wrap_socket(self.server.socket, certfile=cfg.CERT_PATH, keyfile=cfg.KEY_PATH, server_side=True, ssl_version=ssl.PROTOCOL_TLS)


        except Exception as e:
            errno, message = e.args
            if errno == 98 and message == 'Address already in use':
                logger.error('Error starting HTTP(S) server: the port is already in use, try specifying a diffrent port using --server-port')
            else:
                logger.error('Error starting HTTP(S) server: {}'.format(message))

            sys.exit(1)

    def base_server(self):
        return self.server

    def track_host(self, host_ip):
        self.server.hosts.append(host_ip)

    def run(self):
        try:
            self.server.serve_forever()
        except:
            pass

    def shutdown(self):
        try:
            while len(self.server.hosts) > 0:
                self.server.log.info('Waiting on {} host(s)'.format(highlight(len(self.server.hosts))))
                sleep(15)
        except KeyboardInterrupt:
            pass

        # shut down the server/socket
        self.server.shutdown()
        self.server.socket.close()
        self.server.server_close()
        #self._Thread__stop()   #killing threads is inherintly dangerous. need to figure out a way to hanlde this with a stop condition (currently using a timer) in the funciton calling the threads

        # make sure all the threads are killed
        self.server.log.debug('before thread kill')
        for thread in threading.enumerate():
            if thread.isAlive():
                self.server.log.debug('thread-alive check1')
                try:
                    thread.daemon()   #this is a hack, probably need to have conditions that cause threads to end....
                    self.server.log.debug('thread-daemon worked')
                except:
                    self.server.log.debug('thread-daemon failed')
                    pass
