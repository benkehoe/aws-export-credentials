# aws-export-credentials
**Get AWS credentials from a profile to inject into other programs**

There are a number of other projects that extract AWS credentials and/or
inject them into programs, but all the ones I've seen use the CLI's cache
files directly, rather than leveraging botocore's ability to retrieve and
refresh credentials. So I wrote this to do that.

> :warning: If you want to inject refreshable credentials into a locally-run container, [imds-credential-server](https://github.com/benkehoe/imds-credential-server) is a more focused solution for that.

[botocore (the underlying Python SDK library)](https://botocore.amazonaws.com/v1/documentation/api/latest/index.html) has added support for loading credentials cached by [`aws sso login`](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/sso/login.html) as of [version 1.17.0](https://github.com/boto/botocore/blob/develop/CHANGELOG.rst#1170).
`aws-export-credentials` now requires botocore >= 1.17.0, and so supports AWS SSO credentials as well.
If all you want is AWS SSO support for an SDK other than Python, Go, or JavaScript (v3), take a look at [aws-sso-util](https://github.com/benkehoe/aws-sso-util#adding-aws-sso-support-to-aws-sdks), which can help you configure your profiles with a [credential process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) that doesn't require the credential injection process that `aws-export-credentials` does.

## Quickstart

I recommend you install [`pipx`](https://pipxproject.github.io/pipx/), which installs the tool in an isolated virtualenv while linking the script you need.

```bash
# with pipx
pipx install aws-export-credentials

# without pipx
python3 -m pip install --user aws-export-credentials

# run it
aws-export-credentials
{
  "Version": 1,
  "AccessKeyId": "<your access key here>",
  "SecretAccessKey": "<shhh it's your secret key>",
  "SessionToken": "<do you ever wonder what's inside the session token?>"
}
```

You can also download the Python file directly [here](https://raw.githubusercontent.com/benkehoe/aws-export-credentials/stable/aws_export_credentials/aws_export_credentials.py).

## Usage
### Profile
Profiles work like in the AWS CLI (since it uses botocore); it will pick up the `AWS_PROFILE`
or `AWS_DEFAULT_PROFILE` env vars, but the `--profile` argument takes precedence.

### JSON
```
aws-export-credentials --profile my-profile --json [--pretty]
```
Print the credentials to stdout as a JSON object compatible with the `credential_process`
spec. If `--pretty` is added, it'll be pretty-printed.

### Env vars
```
aws-export-credentials --profile my-profile --env
export $(aws-export-credentials --profile my-profile --env)
eval $(aws-export-credentials --profile my-profile --env-export)
```
Print the credentials as environment variables. With `--env-export`, the lines are prefixed
by "`export `".

### Exec wrapper
```
aws-export-credentials --profile my-profile --exec echo 'my access key id is $AWS_ACCESS_KEY_ID'
```
Execute the arguments after `--exec` using `os.system()`, injecting the credentials through
environment variables.

### `~/.aws/credentials`
```
aws-export-credentials --profile my-profile --credentials-file-profile my-exported-profile
aws-export-credentials --profile my-profile -c my-exported-profile
```
Put the credentials in the given profile in your [shared credentials file](https://ben11kehoe.medium.com/aws-configuration-files-explained-9a7ea7a5b42e), which is typically `~/.aws/credentials` but can be controlled using the environment variable [`AWS_SHARED_CREDENTIALS_FILE`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html).

### Credential-serving options
There are two credential-serving options, `--imds` for a server presenting the EC2 IMDSv2 interface, and `--container` for a server presenting the ECS container metadata credentials interface.

> :warning: If you want to inject refreshable credentials into a locally-run container, [imds-credential-server](https://github.com/benkehoe/imds-credential-server) is a more focused solution for that.

#### IMDS
You can use `--imds` to start a server, compliant with [the EC2 IMDSv2 endpoint](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html), that exports your credentials, and this can be used with containers.

You provide `--imds` with a port (you can optionally provide the host part as well).

If you're using docker, map the port from the host to the container, and set the environment variable `AWS_EC2_METADATA_SERVICE_ENDPOINT` to `http://host.docker.internal:MAPPED_PORT/` with the approporiate port and **remember to include the trailing slash.**

AWS SDKs run inside the container should just work.
```bash
# in one terminal
$ aws-export-credentials --imds 8081

# in a separate terminal
$ docker run --rm -p 8081:8081 -e AWS_EC2_METADATA_SERVICE_ENDPOINT=http://host.docker.internal:8081/
amazon/aws-cli sts get-caller-identity
{
    "UserId": "AROAXXXXXXXXXXXXXXXXX:SessionName",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/SomeRole/SessionName"
}
```

#### ECS
> :warning: This method of providing credentials to containers doesn't work well. It only works on Linux using `--network host`. [On Mac](https://docs.docker.com/desktop/mac/networking/#use-cases-and-workarounds) and [Windows](https://docs.docker.com/desktop/windows/networking/#use-cases-and-workarounds), `--network host` is not available, the docker network is always separate. On all three, without `--network host` the host cannot be referenced as `localhost`, only as `host.docker.internal`, which is [not an allowed host the AWS SDKs](https://github.com/boto/botocore/issues/2515).

You can use `--container` to start a server, compliant with the ECS metadata server, that exports your credentials, suitable for use with containers.

You provide `--container` with a port (you can optionally provide the host part as well) and an authorization token.
On your container, map the port from the server, set the `AWS_CONTAINER_CREDENTIALS_FULL_URI` environment variable to the URL as accessed inside the container, and set the `AWS_CONTAINER_AUTHORIZATION_TOKEN` environment variable to the same value you provided the server.

You can use any value for the authorization, but it's best use a random value.

```bash
# Generate token. For example, on Linux:
AWS_CONTAINER_AUTHORIZATION_TOKEN=$(/proc/sys/kernel/random/uuid)

# start the server in the background
aws-export-credentials --profile my-profile --container 8081 $AWS_CONTAINER_AUTHORIZATION_TOKEN &

# run your container
docker run --network host -e AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:8081 -e AWS_CONTAINER_AUTHORIZATION_TOKEN=$AWS_CONTAINER_AUTHORIZATION_TOKEN amazon/aws-cli sts get-caller-identity
```

## Caching
To avoid retrieving credentials every time when using `aws-export-credentials` with the same identity, you can cache the credentials in a file using the `--cache-file` argument.
**Note `aws-export-credentials` does not distinguish in the cache between different identities. Different identities should use different cache files.**
If you do not account for this, credentials may be loaded from the cache and exported that do not correspond to the credentials that would be exported without the cache.
An example of a way to address this would be using a cache file named after the config profile you are exporting.

Cache loading and saving fails silently, to ensure caching does not interrupt usage.
If caching is not working, you can see the details with `--debug`.

By default, cached credentials are considered expired if their expiration is less than 10 minutes in the future.
You can change this value using the `--cache-expiration-buffer` argument, which takes a number of minutes.

You can force the cache to refresh using `--refresh`.

# Role assumption
In general, it's better to do role assumption by using profiles in `~/.aws/config` like this:

```ini
# this is a pre-existing profile you already have
[profile profile-to-call-assume-role-with]
# maybe it's IAM User credentials
# or AWS SSO config
# or whatever else you may have

[profile my-assumed-role]
role_arn = arn:aws:iam::123456789012:role/MyRole
# optional: role_session_name = MyRoleSessionName

source_profile = profile-to-call-assume-role-with
# or instead of source_profile, you can tell it to
# use external credentials. one of:
# credential_source = Environment
# credential_source = Ec2InstanceMetadata
# credential_source = EcsContainer
```

You can then use `my-assumed-role` like any other profile.
It uses the AWS SDKs' built-in support for role assumption, rather than relying on third party code.
It also gets you credential refreshing from the SDKs, where getting the credentials in the manner below cannot refresh them when they expire.

You can then, if needed, export the assumed role credentials with `aws-export-credentials --profile my-assumed-role`.

But if you absolutely must have ad hoc role assumption on the command line, you can accomplish that through [`aws-assume-role-lib`](https://github.com/benkehoe/aws-assume-role-lib#command-line-use).
