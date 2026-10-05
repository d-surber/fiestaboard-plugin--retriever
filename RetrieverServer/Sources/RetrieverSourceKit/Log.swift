import Foundation

/// Sends this program's output to the user's log file, when it is running
/// in the background and not at a terminal. The agents are installed for
/// every account, so the log cannot be named in their launchd files.
public func logToUserFile() {
    guard isatty(STDOUT_FILENO) == 0 else { return }
    let logs = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs", isDirectory: true)
    try? FileManager.default.createDirectory(at: logs, withIntermediateDirectories: true)
    let path = logs.appendingPathComponent("RetrieverServer.log").path
    freopen(path, "a", stdout)
    freopen(path, "a", stderr)
    setvbuf(stdout, nil, _IOLBF, 0)
}

public func log(_ s: String) { print("\(ISO8601DateFormatter().string(from: Date())) \(s)") }
