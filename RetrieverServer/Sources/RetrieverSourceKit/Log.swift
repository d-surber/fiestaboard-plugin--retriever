import Foundation

/// The log every Retriever program in an account writes to. The agents are
/// installed for every account, so it cannot be named in their launchd files.
public enum LogFile {
    /// Past this size the log is set aside as the one earlier log that is
    /// kept, and a new one begun: at most about twice this is ever on disk.
    public static let maxBytes = 1_000_000

    public static func url(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        home.appendingPathComponent("Library/Logs/RetrieverServer.log")
    }

    /// Where the earlier log is kept.
    public static func earlier(_ log: URL) -> URL { log.appendingPathExtension("1") }

    /// Sets the log aside if it has grown past `maxBytes`.
    /// - Returns: true if it did, and the caller's open file is the old one.
    @discardableResult
    public static func rotateIfLarge(_ log: URL, maxBytes: Int = maxBytes) -> Bool {
        let size = (try? FileManager.default.attributesOfItem(atPath: log.path)[.size] as? Int) ?? 0
        guard size > maxBytes else { return false }
        // rename replaces the earlier log in one step.
        return rename(log.path, earlier(log).path) == 0
    }

    /// True if the file open as standard output is no longer the one at
    /// `log`: this program, or another writing the same log, set it aside.
    static func standardOutputHasMoved(from log: URL) -> Bool {
        var open = stat(), named = stat()
        guard fstat(STDOUT_FILENO, &open) == 0 else { return false }
        guard stat(log.path, &named) == 0 else { return true }
        return open.st_ino != named.st_ino || open.st_dev != named.st_dev
    }
}

private var isLoggingToFile = false
private var linesSinceLogCheck = 0
private let linesBetweenLogChecks = 100

/// Sends this program's output to the user's log file, when it is running
/// in the background and not at a terminal.
public func logToUserFile() {
    guard isatty(STDOUT_FILENO) == 0 else { return }
    let file = LogFile.url()
    try? FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
    LogFile.rotateIfLarge(file)
    reopenStandardOutput(at: file)
    isLoggingToFile = true
}

private func reopenStandardOutput(at file: URL) {
    freopen(file.path, "a", stdout)
    freopen(file.path, "a", stderr)
    setvbuf(stdout, nil, _IOLBF, 0)
}

/// Keeps the log from growing without end: every so many lines, sets it
/// aside if it is large, and follows it if another program already has.
private func keepLogBounded() {
    linesSinceLogCheck += 1
    guard isLoggingToFile, linesSinceLogCheck >= linesBetweenLogChecks else { return }
    linesSinceLogCheck = 0
    let file = LogFile.url()
    if LogFile.rotateIfLarge(file) || LogFile.standardOutputHasMoved(from: file) { reopenStandardOutput(at: file) }
}

private let logLock = NSLock()
private let timestamps = ISO8601DateFormatter()

/// Writes one line to the log, with the time before it.
public func log(_ line: String) {
    logLock.lock()
    defer { logLock.unlock() }
    keepLogBounded()
    print("\(timestamps.string(from: Date())) \(line)")
}
