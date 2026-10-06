# System check

This is not part of the plugin's tests. It puts the plugin, running inside a
real FiestaBoard, in front of a server that misbehaves on purpose, and
compares what FiestaBoard renders with what it rendered the last time.

## What it is for

The plugin's own tests (`tests/`) check the plugin's code: given this input,
it does that. They run in seconds and need nothing but a FiestaBoard source
tree. Every fault this check has found in the plugin has a test there.

What those tests cannot see is everything around the plugin:

- what FiestaBoard itself makes of a value: how it renders a list or a null,
  what its formula engine does with an odd number, whether text from a server
  is taken for markup;
- how long things take on the machine FiestaBoard really runs on;
- whether the installed plugin, FiestaBoard and a server work together.

So this is worth running when one of those may have changed:

- after FiestaBoard is upgraded, since its behaviour is half of what is checked;
- after a change to the wire protocol, or to how value rows are worked out;
- before relying on a new kind of server.

It is not worth running on every change. It takes several minutes, some
cases wait out time limits on purpose, and it takes over a plugin instance
and a server while it runs.

## What you need

- A FiestaBoard with the plugin installed, and an API token for it.
- A spare instance of the plugin (by default `retriever:test`), enabled.
  Its value rows are replaced while the check runs and put back afterwards.
- Somewhere to run `misbehaving_server.py` that the instance's server URL
  points at, with the instance's key. If the instance normally points at the
  test server, stop that and run this in its place, on the same port.

## Running it

Start the misbehaving server where the instance will find it:

    RETRIEVER_CHECK_KEY=<the instance's key> python3 misbehaving_server.py

Then, from here:

    export RETRIEVER_CHECK_FIESTABOARD=http://<host>:4420/api/v1
    export RETRIEVER_CHECK_TOKEN_FILE=<file holding the API token>
    export RETRIEVER_CHECK_DELIVER="ssh <host> 'cat > <folder>/scenario.json'"
    python3 run.py

`RETRIEVER_CHECK_DELIVER` is any command that reads a scenario on its
standard input and writes it where the misbehaving server reads it. With the
server on this machine, `cat > scenario.json` will do.

Name one or more groups to run only those: `values`, `limits`, `answers`,
`heavy`. Afterwards, stop the misbehaving server and start the usual one.
The instance goes on showing what it last fetched from the misbehaving
server until its next refresh, which is five minutes away at most; saving a
change to its settings makes it fetch at once.

## Reading the result

Each case is reported as `as expected`, `differs` or `new`. For one that
differs, what was rendered before and what is rendered now are both shown.

A difference is not a failure in itself. It says that something behaves
differently, which is what the check is for; whether that is a fault, an
improvement, or a change in FiestaBoard to adapt to is for a person to
decide. Once the differences are understood and accepted:

    python3 run.py --record

writes what is rendered now to `expected.json` as what to expect from then on.

`expected.json` was recorded on FiestaBoard 9.14.0, on a Raspberry Pi 3,
with a formula engine that returns a result with its type. On a FiestaBoard
whose engine only renders text, values that are numbers here will be text.

The `heavy` group is about size and time, and says more about the machine
than about the code. Its results may differ on a faster or slower machine
without anything being wrong.

## The parts

- `misbehaving_server.py`: the server. Its opening comment describes
  everything a scenario can make it do.
- `cases.py`: the cases, as data: what the server does, the value rows the
  plugin is given, and the templates then rendered.
- `run.py`: runs the cases through FiestaBoard and compares.
- `expected.json`: what was rendered when last recorded.
