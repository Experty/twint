import re
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests

import logging as logme
from decouple import config as envconfig
from fake_useragent import UserAgent
ua = UserAgent(verify_ssl=False)


from decouple import config
from datetime import date
import random


class TokenExpiryException(Exception):
    def __init__(self, msg):
        super().__init__(msg)


class RefreshTokenException(Exception):
    def __init__(self, msg):
        super().__init__(msg)


class Token:
    def __init__(self, config):
        self._session = requests.Session()
        self._session.verify = False
        self._session.headers.update({'User-Agent': f'{ua.random}'})
        self.config = config
        self._retries = 10
        self.rotate_proxy = str(envconfig('ROTATE_PROXY'))
        self._timeout = 10
        self._session.headers.update({'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'})
        self.url = 'https://api.twitter.com/1.1/guest/activate.json'

    def _request(self):
        for attempt in range(self._retries + 1):
            # The request is newly prepared on each retry because of potential cookie updates.
            req = self._session.prepare_request(requests.Request('POST', self.url))
            logme.debug(f'Retrieving {req.url}')
            try:
                if eval((self.rotate_proxy).title()):
                    self.proxies = {
                        "http": f"{str(envconfig('PROXY_URL'))}",
                        "https": f"{str(envconfig('PROXY_URL'))}",
                    }
                    r = self._session.send(req,
                                           allow_redirects=True,
                                           timeout=self._timeout,
                                           proxies=self.proxies
                                           )
                else:
                    proxy = random.choice(self.config.Proxy_list)
                    self.proxies = {
                        "http": f"{str(proxy)}",
                        "https": f"{str(proxy)}",
                    }
                    r = self._session.send(req,
                                           allow_redirects=True,
                                           timeout=self._timeout,
                                           proxies=self.proxies
                                           )
            except requests.exceptions.RequestException as exc:
                if attempt < self._retries:
                    retrying = ', retrying'
                    # level = logme.WARNING
                else:
                    retrying = ''
                    level = logme.ERROR
                # logme.log(level, f'Error retrieving {req.url}: {exc!r}{retrying}')
            else:
                success, msg = (True, None)
                msg = f': {msg}' if msg else ''

                if success:
                    logme.debug(f'{req.url} retrieved successfully{msg}')
                    return r
            if attempt < self._retries:
                # TODO : might wanna tweak this back-off timer
                sleep_time = 2.0 * 2 ** attempt
                logme.info(f'Waiting {sleep_time:.0f} seconds')
                time.sleep(sleep_time)
        else:
            msg = f'{self._retries + 1} requests to {self.url} failed, giving up.'
            logme.fatal(msg)
            self.config.Guest_token = None
            raise RefreshTokenException(msg)

    def refresh(self):
        logme.debug('Retrieving guest token')
        res = self._request()
        res_json = res.json()
        if "guest_token" in res_json.keys():
            logme.debug('Found guest token in HTML')
            self.config.Guest_token = res_json["guest_token"]
        else:
            try:
                headers = {'User-Agent': f'{ua.random}',
                           'authority': 'api.twitter.com',
                           'content-length': '0',
                           'authorization': self.config.Bearer_token,
                           'x-twitter-client-language': 'en',
                           'x-csrf-token': res.cookies.get("ct0"),
                           'x-twitter-active-user': 'yes',
                           'content-type': 'application/x-www-form-urlencoded',
                           'Accept': 'application/json',
                           'sec-gpc': '1',
                           'origin': 'https://twitter.com',
                           'sec-fetch-site': 'same-site',
                           'sec-fetch-mode': 'cors',
                           'sec-fetch-dest': 'empty',
                           'referer': 'https://twitter.com/',
                           'accept-language': 'en-US',
                           }
                self._session.headers.update(headers)
                req = self._session.prepare_request(
                requests.Request('POST', 'https://api.twitter.com/1.1/guest/activate.json'))
                res = self._session.send(req, allow_redirects=True, timeout=self._timeout)
                match = re.search(r'{"guest_token":"(\d+)"}', res.text)
            except requests.exceptions.ConnectionError:
                time.sleep(100)
            if match:
                logme.debug('Found guest token in JSON')
                self.config.Guest_token = str(match.group(1))
            else:
                self.config.Guest_token = None
                raise RefreshTokenException('Could not find the Guest token in JSON')
