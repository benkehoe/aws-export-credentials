# aws-export-credentials
**Get AWS credentials from a profile to inject into other programs**

There are a number of other projects that extract AWS credentials and/or
inject them into programs, but all the ones I've seen use the CLI's cache
files directly, rather than leveraging botocore's ability to retrieve and
refresh credentials. So I wrote this to do that.

One downside to this approach is that it doesn't yet work with AWS SSO
credentials. For that, use aws-sso-credential-process to enable the SDKs
to get credentials AWS SSO. If your tools still don't pick up the
credentials, you can add this on top, for example with `--exec`.

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
eval $(aws-export-credentials --profile my-profile --env-export)
```
Print the credentials as environment variables. With `--env-export`, the lines are prefixed
by "`export `", suitable for eval-ing into your shell.

### Exec wrapper
```
aws-export-credentials --profile my-profile --exec echo 'my access key id is $AWS_ACCESS_KEY_ID'
```
Execute the arguments after `--exec` using `os.system()`, injecting the credentials through
environment variables.
