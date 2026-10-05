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
func connectModules(_ modules: [ModuleConfig.Module]) -> [Source] {
    modules.compactMap { module in
        do {
            return try RemoteSource(service: module.identifier, cdhash: module.cdhash)
        } catch {
            log("\(module.identifier): \(error)")
            return nil
        }
    }
}
