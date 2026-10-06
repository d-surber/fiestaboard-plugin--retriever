import CryptoKit
import Foundation
import RetrieverSourceKit
import Network

setvbuf(stdout, nil, _IOLBF, 0)   // flush log lines immediately under launchd

let port: NWEndpoint.Port = 42511

// Commands that serve nothing and exit; `help` describes them.
let arguments = Array(CommandLine.arguments.dropFirst())
switch arguments.first {
case nil: break   // no command: be the server
case "install": InstallCommand.run()
case "config": ConfigCommand.run(Array(arguments.dropFirst()))
case "status": ConfigCommand.status()
case "log": LogCommand.run(Array(arguments.dropFirst()))
case "help", "--help", "-h":
    print(Help.text(program: ConfigCommand.program))
    exit(0)
default:
    print("Unknown command \"\(arguments[0])\".\n")
    print(Help.text(program: ConfigCommand.program))
    exit(2)
}

logToUserFile()

// The key shared with the plugin belongs to one account. The agents are
// installed for every account; in one with no key there is nothing to serve.
let key = Installation.transportKey(home: FileManager.default.homeDirectoryForCurrentUser).flatMap(Wire.key(base64:))

// What is served: the built-in sources, and the modules a valid, signed,
// unexpired module config lists.
let state = ServerState(builtIn: builtInSources, directory: ConfigStore.installed, builtInKey: ConfigStore.builtInKey(),
                        background: (DispatchQueue(label: "reaching modules"), returningTo: .main), connect: connectModules)
let serverInfo = ServerInfo.current(port: port.rawValue)

guard let key else {
    log("No transport key for this account; not serving.")
    exit(0)
}

// Nothing is being served yet, so the modules can be waited for.
state.refresh(waiting: true)
let listener = RequestListener(key: key, state: state, serverInfo: serverInfo)
do {
    // Advertised by Bonjour so that a HomePod acting as sleep proxy can wake the Mac.
    try listener.start(on: port, advertisedAs: "Retriever") { log(.verbose, "Listener: \($0)") }
} catch {
    log("Failed to start listener: \(error)")
    exit(1)
}

// Look at the module config again every minute: a newly installed one is
// picked up, and an expired one is dropped, without a restart. Modules that
// could not be reached are not retried here, only when a request arrives.
let configTimer = DispatchSource.makeTimerSource(queue: .main)
configTimer.schedule(deadline: .now() + 60, repeating: 60)
configTimer.setEventHandler {
    state.refresh()
    listener.logUnanswered()
}
configTimer.resume()

// Ask every source once now. A source's first fetch may put a permission
// question to the user, as Reminders does after each rebuild, and reports
// "timed out" until it is answered. Better that the question appears at
// startup than on the first request.
retrieve(from: state.sources, timeout: RequestListener.Limits().sourceTimeout) { entries in
    for (name, entry) in entries.sorted(by: { $0.key < $1.key }) where !entry.error.isEmpty {
        log("\(name) at startup: \(entry.error)")
    }
}

dispatchMain()
