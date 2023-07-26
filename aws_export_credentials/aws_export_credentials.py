# Copyright 2020 Ben Kehoe
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import json
import os
import os.path
import sys
import shlex
import traceback
import logging
from datetime import datetime, timezone, timedelta
from collections import namedtuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
import functools
import secrets
import subprocess

from boto3 import Session

__version__ = '0.17.0' # Update here and pyproject.toml

LOGGER = logging.getLogger('aws-export-credentials')

DESCRIPTION ="""\
Get AWS credentials from a profile to inject into other programs.

If you need credentials from AWS SSO,
set up your profiles with aws-sso-util

https://github.com/benkehoe/aws-sso-util
"""

TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

Credentials = namedtuple('Credentials', ['AccessKeyId', 'SecretAccessKey', 'SessionToken', 'Expiration'])
def convert_creds(read_only_creds, expiration=None):
    return Credentials(*list(read_only_creds) + [expiration])

def parse_container_arg(value):
    token = value[1]
    host_post = value[0].rsplit(':', 1)
    if len(host_post) == 1:
        host = ''
        port = int(host_post[0])
    else:
        host = host_post[0]
        port = int(host_post[1])
    return (host, port), token

def parse_imds_arg(value):
    host_post = value.rsplit(':', 1)
    if len(host_post) == 1:
        host = ''
        port = int(host_post[0])
    else:
        host = host_post[0]
        port = int(host_post[1])
    return host, port

def serialize_date(dt):
    if isinstance(dt, str):
        return dt
    return dt.strftime(TIME_FORMAT)

def deserialize_date(dt_str):
    return datetime.strptime(dt_str, TIME_FORMAT).replace(tzinfo=timezone.utc)

def get_credentials(session, ensure_temporary=False, ensure_expiration=False):
    session_credentials = session.get_credentials()
    if not session_credentials:
        return None

    read_only_credentials = session_credentials.get_frozen_credentials()

    if ensure_temporary and not read_only_credentials.token:
        return get_temporary_credentials(session)

    expiration = None

    if hasattr(session_credentials, '_expiry_time') and session_credentials._expiry_time:
        if isinstance(session_credentials._expiry_time, datetime):
            expiration = session_credentials._expiry_time
        else:
            LOGGER.debug("Expiration in session credentials is of type {}, not datetime".format(type(expiration)))

    if not expiration and ensure_expiration:
        # provide an expiration, even if it's wrong
        expiration = datetime.now(tz=timezone.utc) + timedelta(hours=1)

    credentials = convert_creds(read_only_credentials, expiration)
    return credentials

def get_temporary_credentials(session):
    sts_client = session.client('sts')
    response = sts_client.get_session_token()
    response_creds = response['Credentials']

    return Credentials(
        AccessKeyId=response_creds['AccessKeyId'],
        SecretAccessKey=response_creds['SecretAccessKey'],
        SessionToken=response_creds['SessionToken'],
        Expiration=response_creds['Expiration']
    )

def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument('--profile', help='The AWS config profile to use')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--json', action='store_const', const='json', dest='format', help="Print credential_process-compatible JSON to stdout (default)")
    group.add_argument('--env', action='store_const', const='env', dest='format', help="Print as env vars")
    group.add_argument('--env-export', action='store_const', const='env-export', dest='format', help="Print as env vars prefixed by 'export ' for shell sourcing")
    group.add_argument('--exec', nargs=argparse.REMAINDER, help="Exec remaining input w/ creds injected as env vars")
    group.add_argument('--credentials-file-profile', '-c', metavar='PROFILE_NAME', help="Write to a profile in AWS credentials file")
    group.add_argument('--container', nargs=2, metavar=('HOST_PORT', 'TOKEN'), help="Start an ECS-compatible server on [HOST:]PORT, requires TOKEN for auth")
    group.add_argument('--imds', metavar='HOST_PORT', help="Start an IMDSv2 server on [HOST:]PORT")

    parser.add_argument('--ensure-temporary', action='store_true', help='Get temporary credentials for IAM and root users')
    parser.add_argument('--pretty', action='store_true', help='For --json, pretty-print')

    parser.add_argument('--version', action='store_true')
    parser.add_argument('--debug', action='store_true')

    cache_group = parser.add_argument_group('Caching')
    cache_group.add_argument('--cache-file')
    buffer_type = lambda v: timedelta(minutes=int(v))
    buffer_default = timedelta(minutes=10)
    cache_group.add_argument('--cache-expiration-buffer', type=buffer_type, default=buffer_default, metavar='MINUTES', help='Expiration buffer in minutes, defaults to 10 minutes')
    cache_group.add_argument('--refresh', action='store_true', help='Refresh the cache')

    args = parser.parse_args()

    if args.version:
        print(__version__)
        parser.exit()

    if not any([args.format, args.exec, args.credentials_file_profile, args.container, args.imds]):
        args.format = 'json'
        args.pretty = True

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    if args.container:
        try:
            args.container = parse_container_arg(args.container)
        except Exception:
            parser.error("invalid value for --container")
        if args.cache_file:
            parser.error("cannot use --cache-file with --container")
    if args.imds:
        try:
            args.imds = parse_imds_arg(args.imds)
        except Exception:
            parser.error("invalid value for --imds")
        if args.cache_file:
            parser.error("cannot use --cache-file with --imds")

    for key in ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']:
        os.environ.pop(key, None)

    # if args.profile:
    #     for key in ['AWS_PROFILE', 'AWS_DEFAULT_PROFILE']:
    #         os.environ.pop(key, None)

    credentials = None

    if args.cache_file and not args.refresh:
        credentials = load_cache(args.cache_file, args.cache_expiration_buffer)

    if credentials and args.credentials_file_profile:
        session = Session(profile_name=args.profile)
    elif not credentials:
        try:
            session = Session(profile_name=args.profile)

            credentials = get_credentials(session, ensure_temporary=args.ensure_temporary)

            if not credentials:
                print('Unable to locate credentials.', file=sys.stderr)
                sys.exit(2)

            if args.cache_file:
                save_cache(args.cache_file, credentials)
        except Exception as e:
            if args.debug:
                traceback.print_exc()
            print(str(e), file=sys.stderr)
            sys.exit(3)

    if args.exec:
        env = os.environ.copy()

        for key in ['AWS_PROFILE', 'AWS_DEFAULT_PROFILE']:
            env.pop(key, None)

        env.update({
            'AWS_CLI_AUTO_PROMPT': 'off',
            'AWS_ACCESS_KEY_ID': credentials.AccessKeyId,
            'AWS_SECRET_ACCESS_KEY': credentials.SecretAccessKey,
        })
        if credentials.SessionToken:
            env['AWS_SESSION_TOKEN'] = credentials.SessionToken
        if credentials.Expiration:
            env['AWS_CREDENTIAL_EXPIRATION'] = serialize_date(credentials.Expiration)

        region_name = session.region_name
        if region_name:
            env['AWS_DEFAULT_REGION'] = region_name

        command = ' '.join(shlex.quote(arg) for arg in args.exec)
        result = subprocess.run(command, shell=True, env=env)
        sys.exit(result.returncode)
    elif args.format == 'json':
        data = {
            'Version': 1,
            'AccessKeyId': credentials.AccessKeyId,
            'SecretAccessKey': credentials.SecretAccessKey,
        }
        if credentials.SessionToken:
            data['SessionToken'] = credentials.SessionToken
        if credentials.Expiration:
            data['Expiration'] = serialize_date(credentials.Expiration)

        if args.pretty:
            json_kwargs={'indent': 2}
        else:
            json_kwargs={'separators': (',', ':')}

        print(json.dumps(data, **json_kwargs))
    elif args.format in ['env', 'env-export']:
        if args.format == 'env-export':
            prefix = 'export '
        else:
            prefix = ''
        lines = [
            '{}AWS_ACCESS_KEY_ID={}'.format(prefix, credentials.AccessKeyId),
            '{}AWS_SECRET_ACCESS_KEY={}'.format(prefix, credentials.SecretAccessKey),
        ]
        if credentials.SessionToken:
            lines.append('{}AWS_SESSION_TOKEN={}'.format(prefix, credentials.SessionToken))
        if credentials.Expiration:
            lines.append('{}AWS_CREDENTIAL_EXPIRATION={}'.format(prefix, serialize_date(credentials.Expiration)))
        print('\n'.join(lines))
    elif args.credentials_file_profile:
        values = {
            'aws_access_key_id': credentials.AccessKeyId,
            'aws_secret_access_key': credentials.SecretAccessKey,
        }
        if credentials.SessionToken:
            values['aws_session_token'] = credentials.SessionToken
        if credentials.Expiration:
            values['aws_credential_expiration'] = serialize_date(credentials.Expiration)

        write_values(session, args.credentials_file_profile, values)
    elif args.container:
        server_address, token = args.container
        handler_class = functools.partial(ContainerRequestHandler,
            token=token,
            session=session,
        )
        server = HTTPServer(server_address, handler_class)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    elif args.imds:
        server_address = args.imds
        token = secrets.token_urlsafe()
        handler_class = functools.partial(IMDSRequestHandler,
            token=token,
            session=session,
        )
        server = HTTPServer(server_address, handler_class)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    else:
        print("ERROR: no option set (this should never happen)", file=sys.stderr)
        sys.exit(1)

def load_cache(file_path, expiration_buffer):
    try:
        with open(file_path, 'r') as fp:
            data = json.load(fp)
        LOGGER.debug('Loaded cache from {}: {}'.format(file_path, json.dumps(data)))
    except Exception as e:
        LOGGER.debug('Failed to load cache from {}'.format(file_path))
        return None

    try:
        data = data['Credentials']
    except:
        LOGGER.debug('Did not find credentials in cache')
        return None

    try:
        expiration_str = data['Expiration']
    except:
        LOGGER.debug('Did not find expiration in cache')
        return None

    try:
        expiration = deserialize_date(expiration_str)
        data['Expiration'] = expiration
    except Exception as e:
        LOGGER.debug('Could not parse expiration {}: {}'.format(expiration_str, e))
        return None

    try:
        now = datetime.now(tz=timezone.utc)
        if expiration - expiration_buffer < now:
            LOGGER.debug('Cache is expired')
            return None
    except Exception as e:
        LOGGER.debug('Failed checking expiration: {}'.format(e))
        return None

    sanitized_data = {}
    for field in Credentials._fields:
        if field in data:
            sanitized_data[field] = data[field]
        else:
            LOGGER.debug("Field {} missing from cache".format(field))
            return None

    return Credentials(**sanitized_data)

def save_cache(file_path, credentials):
    if not credentials.Expiration:
        LOGGER.debug("Not caching credentials, no expiration")
        return
    try:
        cache_data = {
            'ProviderType': 'aws-export-credentials',
            'Credentials': credentials._asdict()
        }
        cache_data['Credentials']['Expiration'] = serialize_date(credentials.Expiration)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as fp:
            json.dump(cache_data, fp)
        try:
            os.chmod(file_path, 0o600)
        except Exception as e:
            LOGGER.debug('Failed to set cache file mode: {}'.format(e))
        LOGGER.debug('Saved cache to {}: {}'.format(file_path, json.dumps(cache_data)))
    except Exception as e:
        LOGGER.debug('Cache saving failed: {}'.format(e))

try:
    from .config_file_writer import write_values
except ImportError:
    import configparser
    def write_values(session, profile_name, values):
        credentials_file = os.path.expanduser(os.environ.get('AWS_SHARED_CREDENTIALS_FILE') or '~/.aws/credentials')

        parser = configparser.ConfigParser()

        try:
            with open(credentials_file, 'r') as fp:
                parser.read_file(fp)
        except FileNotFoundError:
            pass

        if not parser.has_section(profile_name):
            parser.add_section(profile_name)

        for key, value in values.items():
            parser.set(profile_name, key, value)

        with open(credentials_file, 'w') as fp:
            parser.write(fp)

class ContainerRequestHandler(BaseHTTPRequestHandler):
    # error_message_format = json.dumps({"Error": {"Code": "InvalidRequest", "Message": "%(message)"}})
    # error_content_type = "application/json"

    def __init__(self, request, client_address, server, token, session):
        self._token = token
        self._session = session
        super().__init__(request, client_address, server)

    def do_GET(self):
        if self.path.startswith('/role/') or self.path.startswith('/role-arn/'):
            self.send_response(HTTPStatus.NOT_FOUND)
            body = {"Error": {"Code": "NotImplemented", "Message": "Role assumption is not supported"}}
        if self.path not in ['/', '/creds']:
            self.send_response(HTTPStatus.NOT_FOUND)
            body = {"Error": {"Code": "InvalidPath", "Message": "Only the base path is accepted"}}
        if 'Authorization' not in self.headers:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            body = {"Error": {"Code": "NoAuthorizationHeader", "Message": "Authorization header not provided"}}
        elif self.headers['Authorization'] != self._token:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            body = {"Error": {"Code": "InvalidToken", "Message": "The provided token was invalid"}}
        else:
            self.send_response(HTTPStatus.OK)
            credentials = get_credentials(self._session, ensure_temporary=True, ensure_expiration=True)
            body = {
                'AccessKeyId': credentials.AccessKeyId,
                'SecretAccessKey': credentials.SecretAccessKey,
                'Token': credentials.SessionToken,
                'Expiration': serialize_date(credentials.Expiration)
            }

        body_bytes = json.dumps(body).encode('utf-8')

        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body_bytes))
        self.end_headers()

        self.wfile.write(body_bytes)

class IMDSRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server, token, session):
        self._token = token
        self._session = session
        self._sts_client = self._session.client("sts")
        self._role_name = None
        super().__init__(request, client_address, server)

    def send_error(self, status, code, message):
        self.send_response(status)
        body = {"Error": {"Code": code, "Message": message}}
        body_bytes = json.dumps(body).encode('utf-8')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body_bytes))
        self.end_headers()

        self.wfile.write(body_bytes)

    def send_ok(self, content_type, body):
        self.send_response(HTTPStatus.OK)
        if not isinstance(body, bytes):
            body = json.dumps(body).encode("utf-8")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", len(body))
        self.end_headers()

        self.wfile.write(body)

    def do_PUT(self):
        if self.path != "/latest/api/token":
            return self.send_error(
                HTTPStatus.NOT_FOUND,
                "InvalidPath",
                "Invalid path"
            )

        if self.headers["x-forwarded-for"]:
            return self.send_error(
                HTTPStatus.UNAUTHORIZED,
                "InvalidHeader",
                "PUT requests can't contain X-Forwarded-For"
            )
        if not self.headers["x-aws-ec2-metadata-token-ttl-seconds"]:
            # TODO: the expiration isn't used or enforced
            return self.send_error(
                HTTPStatus.UNAUTHORIZED,
                "MissingToken",
                "The IMDSv2 token expiration header is missing"
            )
        return self.send_ok("text/plain", self._token.encode("ascii"))

    def _ensure_role_name(self):
        if not self._role_name:
            response = self._sts_client.get_caller_identity()
            arn = response["Arn"]
            arn_parts = arn.split(":")
            name_parts = arn_parts[-1].split("/")
            name_type = name_parts[0]
            if name_type == "user":
                role_name = name_parts[-1]
            else:
                role_name = name_parts[1]
            self._role_name = role_name

    def do_GET(self):
        if self.path == "/latest/api/token":
            return self.send_error(
                HTTPStatus.METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "Token must be obtained with PUT"
            )

        if self.headers["x-aws-ec2-metadata-token"] != self._token:
            return self.send_error(
                HTTPStatus.UNAUTHORIZED,
                "MissingToken",
                "The IMDSv2 token header is missing"
            )
        elif self.path == "/latest/meta-data/iam/security-credentials/":
            self._ensure_role_name()
            return self.send_ok("text/plain", self._role_name.encode("ascii"))
        elif self.path.startswith("/latest/meta-data/iam/security-credentials/"):
            self._ensure_role_name()
            role_name = self.path.rsplit("/", 1)[1]
            if role_name != self._role_name:
                return self.send_error(
                    HTTPStatus.FORBIDDEN,
                    "InvalidRoleName",
                    "The role name is incorrect"
                )
            else:
                credentials = get_credentials(self._session, ensure_temporary=True, ensure_expiration=True)
                body = {
                    'AccessKeyId': credentials.AccessKeyId,
                    'SecretAccessKey': credentials.SecretAccessKey,
                    'Token': credentials.SessionToken,
                    'Expiration': serialize_date(credentials.Expiration)
                }
                return self.send_ok("application/json", body)
        return self.send_error(
            HTTPStatus.NOT_FOUND,
            "InvalidPath",
            "Invalid path"
        )

if __name__ == '__main__':
    main()
