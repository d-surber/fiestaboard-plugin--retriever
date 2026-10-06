import Foundation
import RetrieverSourceKit

/// What the server is serving right now: its sources and the config derived
/// from them. Rebuilt when the module config changes on disk, and when it
/// expires, so neither needs a restart.
///
/// Used from one queue only, the server's. Reaching a module can take
/// seconds when the module is not answering, so once the server is serving
/// that is done elsewhere and the result brought back to the server's
/// queue: one module that will not answer delays nothing but itself.
final class ServerState {
    private(set) var sources: [Source] = []
    private(set) var sourceConfig = SourceConfig(sources: [])
    private(set) var verdict: ModuleConfigVerdict = .invalid("not loaded")

    /// A module the config lists has not been reached. It is tried again
    /// when a request arrives, not before: nothing needs it sooner.
    private(set) var hasUnreachedModules = false

    private let builtIn: [Source]
    private let directory: URL
    private let builtInKey: String?
    private let connect: ([ModuleConfig.Module]) -> [Source]
    private let background: (queue: DispatchQueue, returningTo: DispatchQueue)?
    private let configSource = ModuleConfigSource()
    private var lastSeen = ""
    private var lastWarning = ""
    /// The modules reached, each with the entry in the config it was reached for.
    private var reached: [(module: ModuleConfig.Module, source: Source)] = []
    private var isReachingModules = false

    /// - Parameters:
    ///   - builtIn: the sources that run inside the server.
    ///   - connect: reaches the modules it is given; one that cannot be
    ///     reached is left out. May take as long as its slowest module.
    ///   - background: where `connect` runs once the server is serving, and
    ///     the server's queue, to bring the result back to. With none,
    ///     `connect` always runs where `refresh` is called.
    init(builtIn: [Source], directory: URL, builtInKey: String?, background: (queue: DispatchQueue, returningTo: DispatchQueue)? = nil,
         connect: @escaping ([ModuleConfig.Module]) -> [Source]) {
        self.builtIn = builtIn
        self.directory = directory
        self.builtInKey = builtInKey
        self.background = background
        self.connect = connect
    }

    /// Looks at the module config again.
    /// - Parameters:
    ///   - retryingModules: also try again to reach any module not yet reached.
    ///   - waiting: reach the modules before returning, however long that
    ///     takes. For starting up, when there is nobody to keep waiting.
    /// - Returns: true if what is served had changed by the time this returned.
    @discardableResult
    func refresh(now: Date = Date(), retryingModules: Bool = false, waiting: Bool = false) -> Bool {
        let latest = ModuleConfigStore.load(from: directory, builtInKey: builtInKey, now: now)
        warn(latest, now: now)
        let state = "\(ModuleConfigStore.fingerprint(of: directory))|\(latest)"
        let configChanged = state != lastSeen
        guard configChanged || (retryingModules && hasUnreachedModules) else { return false }
        if configChanged, case .invalid(let reason) = latest { log("Module config: \(reason); no modules loaded") }
        lastSeen = state
        verdict = latest
        configSource.verdict = latest

        // A module already reached for the same entry is kept; only the rest
        // are asked for.
        reached = reached.filter { latest.modules.contains($0.module) }
        let unreached = latest.modules.filter { module in !reached.contains { $0.module == module } }
        guard let background, !waiting else {
            noteReached(connect(unreached), of: unreached)
            return serve()
        }
        let changed = serve()
        if !unreached.isEmpty, !isReachingModules {
            isReachingModules = true
            background.queue.async { [connect] in
                let found = connect(unreached)
                background.returningTo.async {
                    self.isReachingModules = false
                    // Only for entries the config still has: it may have changed meanwhile.
                    self.noteReached(found, of: unreached.filter(self.verdict.modules.contains))
                    self.serve()
                }
            }
        }
        return changed
    }

    /// Records which of `asked` were reached, going by the name each source gives itself.
    private func noteReached(_ found: [Source], of asked: [ModuleConfig.Module]) {
        for module in asked where !reached.contains(where: { $0.module == module }) {
            if let source = found.first(where: { Signer.moduleIdentifier(for: $0.name) == module.identifier }) {
                reached.append((module, source))
            }
        }
    }

    /// Makes what is served match the modules reached so far.
    /// - Returns: true if that changed what is served.
    @discardableResult
    private func serve() -> Bool {
        hasUnreachedModules = reached.count < verdict.modules.count
        // In the config's order, so that the order modules answered in changes nothing.
        let modules = verdict.modules.compactMap { module in reached.first { $0.module == module }?.source }
        var names = Set<String>()
        let updated = (builtIn + [configSource] + modules).filter { source in
            let isFirstOfItsName = names.insert(source.name).inserted
            if !isFirstOfItsName { log("A second source named \(source.name) is not served") }
            return isFirstOfItsName
        }
        guard updated.map(\.name) != sources.map(\.name) || SourceConfig(sources: updated).sequenceNumber != sourceConfig.sequenceNumber else { return false }
        sources = updated
        sourceConfig = SourceConfig(sources: sources)
        log("Sources: \(sources.map(\.name).joined(separator: ", ")); config \(sourceConfig.sequenceNumber)")
        return true
    }

    /// One log line a day while the config is within its warning period.
    private func warn(_ verdict: ModuleConfigVerdict, now: Date) {
        guard case .valid(let config) = verdict else { return }
        let warning = config.warning(now: now)
        guard !warning.isEmpty, warning != lastWarning else { return }
        lastWarning = warning
        log("\(warning): sign it again with `RetrieverServer config sign`")
    }
}
