# Command line

`mercurio --help`:

```text
{{#include generated/cli-help.txt}}
```

The short flags are the usual ones for notification tools: `-t` title,
`-b` body, `-n` type, `-c` configuration, `-g` tag. Compatibility notes are
in the [README]({{repository}}#readme).

## Sending

```sh
mercurio -t "Backup" -b "Finished in 42s" ntfy://my-topic "discord://ID/TOKEN"
echo "disk 91% full" | mercurio -n warning tgram://BOT_TOKEN/CHAT_ID
mercurio -c ~/alerts.yml -g devops -b "deploy done"
```

- Without `-b`, the body is read from standard input until end of file.
  A dry run (`-d`) does not read it.
- The title is optional. Services without a title field get it merged into
  the body (see [Messages](messages/index.md)).
- All matching services are notified in parallel, one thread per URL.
  `-Da` sends one after another.
- A word `send` before the URLs is accepted and ignored
  (`mercurio send -b hi ntfy://topic`).

## Verbosity

Without `-v` only errors are printed; `-v` adds warnings
(skipped configuration entries, retries), `-vv` informational messages,
`-vvv` debug and `-vvvv` trace output. Log lines look like `WARNING - ...`.

## Where services come from

The first of these sources that gives anything is used; the rest are
ignored:

1. URLs on the command line. When `-c` is also given, the URLs win and a
   warning is logged (visible with `-v`).
2. `-c / --config` files and URLs.
3. `$APPRISE_URLS`: URLs separated by commas or whitespace.
4. The default configuration files. Every one that exists is loaded.

Put a user configuration in `~/.config/apprise/apprise.conf` and a
system-wide one in `/etc/apprise/apprise.conf` (`.yaml` for YAML), the
locations `--help` shows. For compatibility with older Apprise setups,
every one of these is read, in this order (`{a,b}` is each of `a` and `b`,
the empty entry meaning no extension):

```text
~/.apprise{,.conf,.yml,.yaml}
~/.config/apprise{,.conf,.yml,.yaml}
~/.apprise/apprise{,.conf,.yml,.yaml}
~/.config/apprise/apprise{,.conf,.yml,.yaml}
/etc/apprise{,.yml,.yaml}
/etc/apprise/apprise{,.conf,.yml,.yaml}
```

On Windows they are `Apprise\apprise{,.conf,.yml,.yaml}` under
`%APPDATA%`, `%LOCALAPPDATA%`, `%ALLUSERSPROFILE%`, `%PROGRAMFILES%` and
`%COMMONPROGRAMFILES%`.

Directories are skipped. `$APPRISE_CONFIG_PATH` replaces the whole list
(paths separated by `;` or newlines).

The format of each file (TEXT or YAML) is detected; see
[Configuration files](config/index.md).

## Tags and dry run

`-g` selects configuration entries by tag ([Tags](config/tags.md)); URLs
given on the command line are always notified without `-g`. With `-g`
they are filtered by their `?tag=` values. `-d` loads every source, applies the tags
and prints what would be notified, without sending or reading a body:

```text
$ mercurio -c alerts.yml -g all -d
   1. json://localhost:9/...
      tags: devops
   2. ntfys://ntfy.sh/...
      tags: critical, devops
   3. gotify://${GOTIFY_HOST}/...
       uid: - template; unresolved, would not send -
      tags: home
  template: gotify_host (required)

1 of 3 matched entries could not be resolved and would not be sent.
```

Sending to an unresolved entry fails it; entries that fail to load are
skipped with a warning (`-v` shows them). See [Templates](config/templates.md).

Output is redacted to the scheme and host. For services whose token sits in
the host position (`tgram://BOT_TOKEN/...`) the token is printed; do not
paste dry-run or `storage` output of such URLs in public places.

## URL check

`mercurio check` parses every URL or configuration entry and prints one line per service
(`ok   ntfy:// (ntfy)`, `error: ...`), without applying tags. Exit code 1
when any URL or configuration source is invalid.

## Available services

`mercurio services` lists the services compiled into the binary:

```text
$ mercurio services
46elks                             46elks:// elks://
800.com                            eight00com://
Africas Talking                    atalk://
...
```

`--json` prints details for each service.

## Exit codes

The exit codes are listed at the end of `--help` above.

A URL that fails to parse is reported on stderr and skipped; the other URLs
are still notified. The exit code only counts them. Use `check` first
to catch typos.

## Environment variables

The ones the command line reads are in `--help` above. `APPRISE_CONFIG_DIR`,
`APPRISE_STATELESS_URLS` and `APPRISE_RECURSION_MAX` are for
`mercurio serve` only, see [HTTP server](server.md).
