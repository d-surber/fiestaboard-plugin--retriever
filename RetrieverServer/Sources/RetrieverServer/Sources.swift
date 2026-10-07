import Foundation
import RetrieverSourceKit

// The sources this server serves. The core knows nothing else about them.

/// Sources that run inside the server. There are none: every source is a
/// module, a separate signed program with its own permissions. (The server
/// itself adds one of its own, the module config's state.)
let builtInSources: [Source] = []

/// Reaches the source modules a module config lists: separate signed
/// programs, each named by its signing identifier, which is also its XPC
/// service. A module that is missing, or whose signature is not the server's
/// signer's, is left out and the reason logged.
///
/// Each entry's parameters are put to its module here, once, so that a
/// mistake in the config is reported when the server starts. An entry whose
/// parameters its module will not accept is still served, with that as its
/// error: it is the config that is wrong, and it should show.
///
/// All are asked at once, so this takes as long as the slowest and no
/// longer: at most the time a module is given to describe itself.
func connectModules(_ modules: [ModuleConfig.Module]) -> [Source] {
    var reached = [Source?](repeating: nil, count: modules.count)
    let lock = NSLock()
    DispatchQueue.concurrentPerform(iterations: modules.count) { position in
        let module = modules[position]
        do {
            let source = try RemoteSource(serviceName: module.identifier, cdhash: module.cdhash, name: module.name,
                                          parameters: module.parameters ?? [:])
            if let problem = source.parameterProblem {
                log("Module config: the source \"\(source.name)\" (\(module.identifier)) \(problem). It reports that until the config is corrected.")
            }
            lock.withLock { reached[position] = source }
        } catch {
            log("\(module.sourceName) (\(module.identifier)): \(error)")
        }
    }
    return reached.compactMap { $0 }
}
