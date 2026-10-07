import Foundation

/// `RetrieverServer help`: every command, who runs it, and in what order.
enum Help {
    /// The whole of the help. `program` is not used in it: the text names the installed copy, which is the one to run.
    static func text(program: String) -> String {
        """
        RetrieverServer serves data from this Mac to the Retriever plugin for FiestaBoard.

        Run with no command, it is the server itself; launchd does that. The commands
        below serve nothing and exit. Run them from the installed copy:
          \(Installation.programs.path)/\(Installation.serverName)

        HOW IT FITS TOGETHER
          The server has no data of its own. Each source of data is a module: a
          separate program holding only the permission its own source needs. Two
          checks decide whether a module is used:
            1. Its code signature. The server and its modules only talk to programs
               signed by the same signer as themselves.
            2. The module config. The server loads only the modules listed in a
               signed, unexpired config. Signing it needs you in person (Touch ID
               or your password); installing it needs an administrator.

        SETTING UP, IN ORDER
          sudo ./RetrieverServer install
              Run from the folder holding the server and module programs. Copies
              them to \(Installation.programs.path), owned by root, and sets up the
              launchd agents in \(Installation.launchAgents.path). Signs nothing: each copy
              is checked once it is there, and one not signed by this server's
              signer is not installed. Makes the transport key
              if this account has none, and prints it for the plugin's settings.

          RetrieverServer config sign
              As yourself. With no config yet, proposes every installed module,
              shows the list, and signs it. The first signing creates the config
              key in this Mac's Secure Enclave.

          sudo RetrieverServer config install
              Checks the signed config, puts it where the server reads it, and
              shows what it allows. The server picks it up within a minute; no
              restart is needed. The first install also installs the config key,
              and shows its fingerprint, which should be the one shown at
              signing. After that a config signed with any other key is refused,
              unless you add --replace-key to change the key on purpose.

        CHANGING WHAT IS ALLOWED  (as yourself, then: sudo RetrieverServer config install)
          Each change is signed as it is made and waits to be installed. Several
          can be made one after another and installed together.

          RetrieverServer config add <module program or identifier> [--pin]
              Allows a module's source, under the module's own name. --pin
              allows only that exact build, so a rebuilt module must be added
              again.

          RetrieverServer config add <module> --name <name> [--set <parameter>=<value> ...]
              Allows a source under a name of your choosing, and says what its
              module is to be asked. A module that takes parameters can be
              listed as often as you like, each time under another name:
                config add local.retriever-source.calendar --name today
                config add local.retriever-source.calendar --name tomorrow --set days_from_today=1
              A name is lower-case letters, digits and underscores. A value
              that reads as a number or as true or false is one; put it in
              quotes to make it text. The module is asked whether it takes
              these before they are signed, and again when the server starts:
              a source with parameters its module will not take is served
              with that as its error.

          RetrieverServer config remove <source name or module identifier>
              Stops allowing a source, or every source of a module.

          RetrieverServer config sign [identifier ...]
              Signs the current list again, which renews its expiry. Naming
              modules replaces the list with exactly those.

          All three take --days N. A config is valid for \(Int(ModuleConfig.defaultValidity / 86400)) days unless you say
          otherwise. From \(ModuleConfig.warningDays) days before it expires the server warns daily, in
          its log and to the board as retriever.module_config.data.warning. When
          it expires, no modules are loaded until a new one is installed.

        LOOKING
          RetrieverServer status
              The installed modules and the parameters each takes, the
              transport key, which config key is trusted, whether the config
              is valid and when it expires, and whether each source it allows
              can be reached.

          RetrieverServer log [none | terse | verbose | debug]
              How much is written to the log. With no level, shows the one in
              force. Each level includes those before it: terse (the standard)
              is starting, what is served and whatever goes wrong; verbose adds
              each request answered and a count of connections that were not;
              debug adds each source's answer and how long it took. The server
              and its modules follow a change within a few seconds.

          RetrieverServer help
              This text.

        WHERE THINGS ARE
          Programs        \(Installation.programs.path)           (root)
          Module config   \(ModuleConfigStore.installedFolder.path)/config.json, config.sig  (root)
          SourceConfig key      \(ModuleConfigStore.installedFolder.path)/config-key.pub           (root)
          Launchd agents  \(Installation.launchAgents.path)/local.retriever-*.plist                  (root)
          Transport key   ~/Library/Application Support/Retriever/transport.key      (yours only)
          Log             ~/Library/Logs/RetrieverServer.log                         (kept under about 2 MB)
          Log level       ~/Library/Application Support/Retriever/log-level          (yours)

        SIGNING A CONFIG ELSEWHERE
          A config can be signed on another machine with ordinary tools, keeping
          the key off this Mac:
            openssl dgst -sha256 -sign key.pem -out config.sig config.json
          Building the server with that key's public half in config-key.pub makes
          it the only config key the server trusts.
        """
    }
}
