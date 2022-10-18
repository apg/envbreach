# envbreach: Fill your environment with Vault secrets.

What now? When writing a 12 Factor app, its suggested that you configure
everything with environment variables, including passwords, and other
sensitive data. This sensitive data shouldn't be on disk, and luckily, it
doesn't have to be; it can be stored in Vault.

## Usage

```
$ cat .env
HOME="${HOME}"
PASSWORD="${vault:///v1/secret/data/user#data.data.password}"
USERNAME="${vault:///v1/secret/data/user#data.data.user}"
INTERVIEW="Interviewer: Hello, ${USER}! Thanks for joining me.
${USER}: My pleasure!
Interviewer: You wrote this utility to show off an intuitive way to do
  12 Factor with Vault, is that correct?
${USER}: Why yes it is, Bob. Yes it is."
# What's the PASSWORD?
$ envbreach python -c "import os; print os.environ['PASSWORD']"
hunter2
# Now show what the full environment is when running.
$ envbreach env
HOME=/home/apg
PASSWORD=hunter2
USERNAME=apg
INTERVIEW=Interviewer: Hello, apg! Thanks for joining me.
apg: My pleasure!
Interviewer: You wrote this utility to show off an intuitive way to do
  12 Factor with Vault, is that correct?
apg: Why yes it is, Bob. Yes it is.
```

This assumes that the following is in `envbreach`'s environment:

* `APPROLE_ROLE_PATH`: Mount path for the approle engine. Or `-a path`.
* `APPROLE_ROLE_ID`: Role ID for the approle. Or `-r role_id`.
* `APPROLE_SECRET_ID`: Secret ID for the approle. Or `-s
  secret_id`. Note that this does not support response wrapped secrets
  at the moment.
* `VAULT_ADDR`: As normal. Or `-addr vault_addr`.
* `VAULT_NAMESPACE`: As normal. Or `-namespace namespace`.

An alternative file to `.env` is provided with `-e envfile`.

### Envfile

The envfile is the standard `KEY=value` Unix environment
variables. These can be quoted, and if they are quoted, can also be
multiline. Quotes within a quoted string can also be escaped via `\"`.

The use of `${ ... }` triggers substitution with the following rules:

`${vault:///path/to/something#JSON.keys.to.select}`: Using the
configured approle, login and read `/path/to/something` from
Vault. The JSON returned is then traversed as nested maps through the
keys `[JSON, keys, to, select]`, and the final thing there is
stringified and substituted.

`${ENV}`: Expands to the environment variable `$ENV` for the purposes
of explicit export of `envbreach`'s environment. In this way, you can
hide `APPROLE_SECRET_ID` as `envbreach` doesn't pass it on by default.


## Probable Bugs / Short comings

* Only basic approle support
* Code is a mess, but this is a Hack Week project
* No explicit way to escape `{` or `}` in env values, so that might be
  surprising.

## Copyright

(c) 2022, Andrew Gwozdziewycz: web@apgwoz.com

See LICENSE file for more information.

