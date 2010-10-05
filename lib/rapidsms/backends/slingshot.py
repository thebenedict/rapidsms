#!/usr/bin/env python
# vim: ai ts=4 sts=4 et sw=4 encoding=utf-8

"""
SlingshotSMS backend for RapidSMS

<<SLINGSHOT URL>>

Based on backends.http in RapidSMS core, with modifications by Michael Benedict and Tom MacWright.

To use the SlingshotSMS backend, add to settings.py:

    "my_slingshot_backend" : {"ENGINE":  "rapidsms.backends.slingshot", 
                "port": 8888,
                "public_key": "my_public_key",
                "private_key": "my_private_key",
                "slingshot_url": "http://myslingshoturl.com/",
        }

Include a trailing slash on slingshot_url as above.

Public and private keys can be any string, and both must be specified in settings.py and in slingshotsms.txt. The private key is only private in that it is never sent in get parameters without being hashed.

"""

import json
import hmac
import urllib2
import urllib
import select
from hashlib import sha1
from datetime import datetime

from django import http
from django.http import HttpResponse, HttpResponseBadRequest
from django.core.handlers.wsgi import WSGIHandler, STATUS_CODE_TEXT
from django.core.servers.basehttp import WSGIServer, WSGIRequestHandler

from rapidsms.log.mixin import LoggerMixin
from rapidsms.backends.base import BackendBase


class RapidWSGIHandler(WSGIHandler, LoggerMixin):
    """ WSGIHandler without Django middleware and signal calls """

    def _logger_name(self):
        return "%s/%s" % (self.backend._logger_name(), 'handler')

    def __call__(self, environ, start_response):
        request = self.request_class(environ)
        self.debug('Request from %s' % request.get_host())
        try:
            response = self.backend.handle_request(request)
        except Exception, e:
            self.exception(e)
            response = http.HttpResponseServerError()
        try:
            status_text = STATUS_CODE_TEXT[response.status_code]
        except KeyError:
            status_text = 'UNKNOWN STATUS CODE'
        status = '%s %s' % (response.status_code, status_text)
        response_headers = [(str(k), str(v)) for k, v in response.items()]
        start_response(status, response_headers)
        return response


class RapidHttpServer(WSGIServer):
    """ WSGIServer that doesn't block on handle_request """

    def handle_request(self, timeout=1.0):
        reads, writes, errors = (self, ), (), ()
        reads, writes, errors = select.select(reads, writes, errors, timeout)
        if reads:
            WSGIServer.handle_request(self)


class RapidHttpBacked(BackendBase):
    """ RapidSMS backend that creates and handles an HTTP server """

    _title = "SLINGSHOT"

    def configure(self, host="localhost", port=8080, 
                        public_key="my_public_key", private_key="my_private_key", 
                        slingshot_url="http://myslingshoturl.com"):
        self.host = host
        self.port = port
        self.handler = RapidWSGIHandler()
        self.handler.backend = self
        self.private_key = private_key
        self.slingshot_url = slingshot_url

    def run(self):
        server_address = (self.host, int(self.port))
        self.info('Starting HTTP server on {0}:{1}'.format(*server_address))
        self.server = RapidHttpServer(server_address, WSGIRequestHandler)
        self.server.set_app(self.handler)
        while self.running:
            self.server.handle_request()

    # Verify a message.
    def keyauth_verify(self, public_key, message, nonce, timestamp, hsh):
        hashobj = hmac.new(self.private_key, message + nonce + timestamp, sha1)
        return hsh == hashobj.hexdigest()

    def handle_request(self, request):
        if not self.keyauth_verify('test',request.POST['message'],request.POST['nonce'],request.POST['timestamp'],request.POST['hash']):
            self.debug('Could not verify message, check public/private key in slingshotsms.txt and settings.py')
            return HttpResponseBadRequest("Authentication failed, please check your configuration")
        jsn = json.loads(request.POST['message'])
        self.debug(json.dumps(jsn, sort_keys=True, indent=4))
        sms = jsn[0]['text']
        sender = jsn[0]['sender']
        now = datetime.utcnow()
        try:
            msg = super(RapidHttpBacked, self).message(sender, sms, now)
        except Exception, e:
            self.exception(e)
            raise        
        self.route(msg)
        return HttpResponse('OK') 
    
    def send(self, message):
        self.info('Sending message: %s' % message)
        #send the message with the URL format Slingshot expects
        #example: http://localhost:8080/send?data=[{%22number%22:5551212,%20%22text%22:%20%22blah%22}]
        url = "%ssend?data=[%s]" % (self.slingshot_url, urllib.quote_plus(json.dumps({'text': message.text,
                   'number': message.connection.identity})))
        try:
            self.debug('Sending: %s' % url)
            response = urllib2.urlopen(url)
        except Exception, e:
            self.exception(e)
            return
        self.info('SENT')
        self.debug(response)
