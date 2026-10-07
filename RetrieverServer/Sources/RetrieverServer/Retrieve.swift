import Foundation
import RetrieverSourceKit

/// Asks every source for its data and calls `done`, on `queue`, with an entry
/// for each. A source that has not answered within `timeout` is reported as
/// such, so one slow source cannot hold up the others. Of two sources with
/// one name, the first to answer is the one reported.
func retrieve(from sources: [Source], timeout: TimeInterval, on queue: DispatchQueue = .main, _ done: @escaping ([String: Entry]) -> Void) {
    var entries: [String: Entry] = [:]   // only touched on `queue`
    let asked = Date()
    let namesToHearFrom = Set(sources.map(\.name)).count
    var finished = false
    func finish() {
        guard !finished else { return }
        finished = true
        for source in sources where entries[source.name] == nil {
            log("\(source.name) did not answer in \(timeout) s")
            entries[source.name] = source.failed("timed out")
        }
        done(entries)
    }
    queue.async {
        for source in sources {
            source.fetch(parameters: [:]) { entry in
                queue.async {
                    guard !finished, entries[source.name] == nil else { return }
                    entries[source.name] = entry
                    log(.debug, "\(source.name) answered in \(Int(Date().timeIntervalSince(asked) * 1000)) ms"
                                + (entry.error.isEmpty ? "" : ": \(entry.error)"))
                    if entries.count == namesToHearFrom { finish() }
                }
            }
        }
        if sources.isEmpty { finish() }
    }
    queue.asyncAfter(deadline: .now() + timeout) { finish() }
}
