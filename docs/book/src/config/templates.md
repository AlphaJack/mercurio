# Templates

A YAML configuration can leave parts of its URLs open as `${NAME}`
variables, filled when a notification is sent. In TEXT files `${NAME}` is
plain text.

```yaml
version: 1
template:
  - host: ntfy.sh      # has a default
  - topic              # required
urls:
  - ntfys://${HOST}/${TOPIC}:
      tag: alerts
  - json://localhost:8080/${TOPIC}
```

```sh
mercurio -c tmpl.yml -g all -tv topic=backups -b "done"
APPRISE_TEMPLATE_TOPIC=backups mercurio -c tmpl.yml -g alerts -b "done"
```

## Declaring variables

`template:` is a list (as above) or a mapping (`topic: ~` for required,
`host: ntfy.sh` for a default).

- Names are 1 to 32 letters, digits or `_`, case-insensitive: `${host}`,
  `${HOST}` and `-tv Host=...` are the same variable.
- A default is text, a number or a boolean.
- A name declared twice, an invalid name or an invalid default rejects the
  whole file.
- Only declared names are replaced; an undeclared `${OTHER}` stays as
  written.

## Where values come from

The first available value wins:

1. `-tv NAME=VALUE` (`--template-var`, repeatable), `TemplateVars` in the
   library or the server request's `template` field.
2. The default in `template:`.
3. `APPRISE_TEMPLATE_NAME` in the environment (the name in upper case).

An empty value counts as not given. A value may be at most 1,024
characters without control characters; the URL after substitution at most
8,192. `-tv` without `=`, with an invalid name or naming a variable twice
ends the command with exit code 2; the error shows the name, never the
value.

## Pending entries

An entry with variables is parsed at load time and kept pending until a
notification supplies the values. `check` marks it
(`ok   json:// (JSON) (template: topic)`). A dry run shows what is
missing:

```text
$ mercurio -d -g all -c tmpl.yml
   1. ntfys://${HOST}/...
       uid: - template; unresolved, would not send -
      tags: alerts
  template: host (has default), topic (required)
   2. json://localhost:8080/...
       uid: - template; unresolved, would not send -
  template: topic (required)

2 of 2 matched entries could not be resolved and would not be sent.
```

At send time an entry whose variables cannot all be resolved fails in the
report; the others are sent.

## Where variables may appear

Values go into the parsed URL field they were written in, after parsing. A
value in the host cannot add a path or a query. A `/` or `@` in a value
does not change the URL's structure. A host value may carry a port
(`example.com:8080`) when the URL has none.

| Position | Allowed |
|---|---|
| user, password, host, port, path, query values, settings under the URL | yes |
| the scheme, `tag` / `tags`, a part the service's parser discards | no: the entry is skipped with a warning |
