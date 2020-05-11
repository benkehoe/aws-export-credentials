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
import subprocess

from botocore.session import Session

DESCRIPTION ="""\
Get AWS credentials from a profile to inject into other programs.

If you need credentials from AWS SSO, first set up aws-sso-credential-process
https://github.com/benkehoe/aws-sso-credential-process
"""

def main():


    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument('--profile', help='The AWS config profile to use')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--json', action='store_const', const='json', dest='format', help="Print credential_process-compatible JSON to stdout (default)")
    group.add_argument('--env', action='store_const', const='env', dest='format', help="Print as env vars")
    group.add_argument('--env-export', action='store_const', const='env-export', dest='format', help="Print as env vars prefixed by 'export ' for shell sourcing")
    group.add_argument('--exec', nargs=argparse.REMAINDER, help="Exec remaining input w/ creds injected as env vars")

    group.add_argument('--pretty', action='store_true', help='For --json, pretty-print')

    args = parser.parse_args()

    if not any([args.format, args.exec]):
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
        os.system(' '.join(args.exec))
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

if __name__ == '__main__':
    main()
