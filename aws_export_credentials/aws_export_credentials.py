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
import textwrap
import os
import sys
import shlex

from botocore.session import Session

__version__ = '0.4.0'

DESCRIPTION ="""\
Get AWS credentials from a profile to inject into other programs.

If you need credentials from AWS SSO,
set up your profiles with aws-sso-util

https://github.com/benkehoe/aws-sso-util
"""

def main():


    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument('--profile', help='The AWS config profile to use')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--json', action='store_const', const='json', dest='format', help="Print credential_process-compatible JSON to stdout (default)")
    group.add_argument('--env', action='store_const', const='env', dest='format', help="Print as env vars")
    group.add_argument('--env-export', action='store_const', const='env-export', dest='format', help="Print as env vars prefixed by 'export ' for shell sourcing")
    group.add_argument('--exec', nargs=argparse.REMAINDER, help="Exec remaining input w/ creds injected as env vars")
    group.add_argument('--credentials-file-profile', '-c', metavar='PROFILE_NAME', help="Write to a profile in AWS credentials file")

    parser.add_argument('--pretty', action='store_true', help='For --json, pretty-print')

    parser.add_argument('--version', action='store_true')

    args = parser.parse_args()

    if args.version:
        print(__version__)
        parser.exit()

    if not any([args.format, args.exec, args.credentials_file_profile]):
        args.format = 'json'
        args.pretty = True

    for key in ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']:
        os.environ.pop(key, None)

    session = Session(profile=args.profile)

    credentials = session.get_credentials().get_frozen_credentials()

    if args.exec:
        os.environ.update({
            'AWS_ACCESS_KEY_ID': credentials.access_key,
            'AWS_SECRET_ACCESS_KEY': credentials.secret_key,
        })
        if credentials.token:
            os.environ['AWS_SESSION_TOKEN'] = credentials.token
        command = ' '.join(shlex.quote(arg) for arg in args.exec)
        os.system(command)
    elif args.format == 'json':
        data = {
            'Version': 1,
            'AccessKeyId': credentials.access_key,
            'SecretAccessKey': credentials.secret_key,
        }
        if credentials.token:
            data['SessionToken'] = credentials.token

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
            f'{prefix}AWS_ACCESS_KEY_ID={credentials.access_key}',
            f'{prefix}AWS_SECRET_ACCESS_KEY={credentials.secret_key}',
        ]
        if credentials.token:
            lines.append(f'{prefix}AWS_SESSION_TOKEN={credentials.token}')
        print('\n'.join(lines))
    elif args.credentials_file_profile:
        values = {
            'aws_access_key_id': credentials.access_key,
            'aws_secret_access_key': credentials.secret_key,
        }
        if credentials.token:
            values['aws_session_token'] = credentials.token

        write_values(session, args.credentials_file_profile, values)
    else:
        print("ERROR: no option set (this should never happen)", file=sys.stderr)
        sys.exit(1)

try:
    from .config_file_writer import write_values
except ImportError:
    import configparser
    def write_values(session, profile_name, values):
        credentials_file = os.path.expanduser(os.environ.get('AWS_SHARED_CREDENTIALS_FILE') or '~/.aws/credentials')

        parser = configparser.ConfigParser()

        with open(credentials_file, 'r') as fp:
            parser.read_file(fp)

        if not parser.has_section(profile_name):
            parser.add_section(profile_name)

        for key, value in values.items():
            parser.set(profile_name, key, value)

        with open(credentials_file, 'w') as fp:
            parser.write(fp)


if __name__ == '__main__':
    main()
