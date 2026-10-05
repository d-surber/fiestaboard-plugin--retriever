import Foundation
import RetrieverSourceKit

/// What the server is serving right now: its sources and the config derived
/// from them. Rebuilt when the module config changes on disk, and when it
/// expires, so neither needs a restart.
final class ServerState {
    private(set) var sources: [Source] = []
    private(set) var config = Config(sources: [])
    private(set) var verdict: ConfigVerdict = .invalid("not loaded")

    private let builtIn: [Source]
    private let directory: URL
    private let builtInKey: String?
    private let connect: ([ModuleConfig.Module]) -> [Source]
    private let configSource = ConfigSource()
    private var seen = ""
    /// A module the config lists could not be reached. It is tried again
    /// when a request arrives, not before: nothing needs it sooner.
    private(set) var incomplete = false
    private var lastWarning = ""

    /// - Parameters:
    ///   - builtIn: the sources that run inside the server.
    ///   - connect: reaches the modules a valid config lists; one that cannot be reached is left out.
    init(builtIn: [Source], directory: URL, builtInKey: String?, connect: @escaping ([ModuleConfig.Module]) -> [Source]) {
        self.builtIn = builtIn
        self.directory = directory
        self.builtInKey = builtInKey
        self.connect = connect
    }

    /// Looks at the module config again. With `retryingModules`, also tries
    /// again to reach any module that could not be reached before. Returns
    /// true if what is served changed.
    @discardableResult
    func refresh(now: Date = Date(), retryingModules: Bool = false) -> Bool {
        let latest = ConfigStore.load(from: directory, builtInKey: builtInKey, now: now)
        warn(latest, now: now)
        let state = "\(ConfigStore.fingerprint(of: directory))|\(latest)"
        guard state != seen || (retryingModules && incomplete) else { return false }
        if state != seen, case .invalid(let reason) = latest { log("Module config: \(reason); no modules loaded") }
        seen = state
        verdict = latest
        configSource.verdict = latest
        let modules = connect(latest.modules)
        incomplete = modules.count < latest.modules.count
        let updated = builtIn + [configSource] + modules
        guard updated.map(\.name) != sources.map(\.name) || Config(sources: updated).seq != config.seq else { return false }
        sources = updated
        config = Config(sources: sources)
        log("Sources: \(sources.map(\.name).joined(separator: ", ")); config \(config.seq)")
        return true
    }

    /// One log line a day while the config is within its warning period.
    private func warn(_ verdict: ConfigVerdict, now: Date) {
        guard case .valid(let config) = verdict else { return }
        let warning = config.warning(now: now)
        guard !warning.isEmpty, warning != lastWarning else { return }
        lastWarning = warning
        log("\(warning): sign it again with `RetrieverServer config sign`")
    }
}
