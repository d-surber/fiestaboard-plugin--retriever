import Foundation

/// `RetrieverServer help`: every command, who runs it, and in what order.
enum Help {
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
              launchd agents in \(Installation.launchAgents.path). Signs nothing: programs not
              signed by this server's signer are skipped. Makes the transport key
              if this account has none, and prints it for the plugin's settings.

          RetrieverServer config sign
              As yourself. With no config yet, proposes every installed module,
              shows the list, and signs it. The first signing creates the config
              key in this Mac's Secure Enclave.

          sudo RetrieverServer config install
              Checks the signed config and puts it where the server reads it. The
              server picks it up within a minute; no restart is needed.

        CHANGING WHAT IS ALLOWED  (as yourself, then: sudo RetrieverServer config install)
          RetrieverServer config add <module program or identifier> [--pin]
              Allows a module. --pin allows only that exact build, so a rebuilt
              module must be added again.

          RetrieverServer config remove <identifier>
              Stops allowing a module.

          RetrieverServer config sign [identifier ...]
              Signs the current list again, which renews its expiry. Naming
              modules replaces the list with exactly those.

          All three take --days N. A config is valid for \(Int(ModuleConfig.validity / 86400)) days unless you say
          otherwise. From \(ModuleConfig.warningDays) days before it expires the server warns daily, in
          its log and to the board as retriever.module_config.data.warning. When
          it expires, no modules are loaded until a new one is installed.

        LOOKING
          RetrieverServer status
              The installed modules, the transport key, which config key is
              trusted, whether the config is valid and when it expires, and
              whether each module it allows can be reached.

          RetrieverServer help
              This text.

        WHERE THINGS ARE
          Programs        \(Installation.programs.path)           (root)
          Module config   \(ConfigStore.installed.path)/config.json, config.sig  (root)
          Config key      \(ConfigStore.installed.path)/config-key.pub           (root)
          Launchd agents  \(Installation.launchAgents.path)/local.retriever-*.plist                  (root)
          Transport key   ~/Library/Application Support/Retriever/transport.key      (yours only)
          Log             ~/Library/Logs/RetrieverServer.log

        SIGNING A CONFIG ELSEWHERE
          A config can be signed on another machine with ordinary tools, keeping
          the key off this Mac:
            openssl dgst -sha256 -sign key.pem -out config.sig config.json
          Building the server with that key's public half in config-key.pub makes
          it the only config key the server trusts.
        """
    }
}
