import RetrieverSourceKit

// The sources this server serves: the one place they are listed. The core
// knows nothing else about them.

/// Sources that still run inside the server.
let allSources: [Source] = [RemindersSource(), MusicSource()]

/// Sources that run as modules: separate signed programs, named here by
/// their XPC service. A module that is missing, or whose signature is not
/// the server's signer's, is left out and the reason logged.
let moduleServices = [Signer.moduleIdentifier(for: "os")]

func connectModules() -> [Source] {
    moduleServices.compactMap { service in
        do {
            return try RemoteSource(service: service)
        } catch {
            log("\(service): \(error)")
            return nil
        }
    }
}
