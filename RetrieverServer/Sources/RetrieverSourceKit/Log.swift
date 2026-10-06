import Foundation

/// How much a Retriever program writes to the log. Each level includes the
/// ones before it.
public enum LogLevel: String, CaseIterable, Comparable {
    /// Nothing at all.
    case none
    /// What an owner needs to know: starting, what is served, and whatever went wrong.
    case terse
    /// Also the routine: each request answered, and how many connections were not.
    case verbose
    /// Also what helps find a fault: each source's answer and how long it took.
    case debug

    public static let standard = LogLevel.terse

    public static func < (first: LogLevel, second: LogLevel) -> Bool {
        allCases.firstIndex(of: first)! < allCases.firstIndex(of: second)!
    }

    /// The level a word names, ignoring case and surrounding space; nil if it names none.
    public init?(named word: String) {
        self.init(rawValue: word.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
    }
}

/// Where the account's choice of log level is kept, and how it is read.
///
/// It is a one-word file in the account's own folder, read by the server
/// and by every module, so one choice governs the whole log. A program
/// looks at it again every few seconds, so a change needs no restart.
public enum LogSettings {
    public static func file(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        home.appendingPathComponent("Library/Application Support/Retriever/log-level")
    }

    /// The level the file names; the standard level if there is no file or it names none.
    public static func level(in file: URL) -> LogLevel {
        guard let word = try? String(contentsOf: file, encoding: .utf8) else { return .standard }
        return LogLevel(named: word) ?? .standard
    }

    /// Records the account's choice.
    /// - Throws: if the file cannot be written.
    public static func set(_ level: LogLevel, in file: URL) throws {
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data((level.rawValue + "\n").utf8).write(to: file, options: .atomic)
    }

    static let secondsBetweenReadings: TimeInterval = 5
}

/// The log every Retriever program in an account writes to. The agents are
/// installed for every account, so it cannot be named in their launchd files.
public enum LogFile {
    /// Past this size the log is set aside as the one earlier log that is
    /// kept, and a new one begun: at most about twice this is ever on disk.
    public static let maxByteCount = 1_000_000

    public static func url(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        home.appendingPathComponent("Library/Logs/RetrieverServer.log")
    }

    /// Where the earlier log is kept.
    public static func earlier(_ log: URL) -> URL { log.appendingPathExtension("1") }

    /// Sets the log aside if it has grown past `maxByteCount`.
    /// - Returns: true if it did, and the caller's open file is the old one.
    @discardableResult
    public static func rotateIfLarge(_ log: URL, maxByteCount: Int = maxByteCount) -> Bool {
        let size = (try? FileManager.default.attributesOfItem(atPath: log.path)[.size] as? Int) ?? 0
        guard size > maxByteCount else { return false }
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

/// What one program knows about its own logging. Guarded by `logLock`.
private struct Logging {
    var isWritingToFile = false
    var linesSinceFileCheck = 0
    var level = LogLevel.standard
    var levelReadAt = Date.distantPast
    let timestamps = ISO8601DateFormatter()
    static let linesBetweenFileChecks = 100

    /// The account's level, read again if the last reading is old.
    mutating func currentLevel(now: Date) -> LogLevel {
        if now.timeIntervalSince(levelReadAt) >= LogSettings.secondsBetweenReadings {
            level = LogSettings.level(in: LogSettings.file())
            levelReadAt = now
        }
        return level
    }

    /// Keeps the log from growing without end: every so many lines, sets it
    /// aside if it is large, and follows it if another program already has.
    mutating func keepFileBounded() {
        linesSinceFileCheck += 1
        guard isWritingToFile, linesSinceFileCheck >= Logging.linesBetweenFileChecks else { return }
        linesSinceFileCheck = 0
        let file = LogFile.url()
        if LogFile.rotateIfLarge(file) || LogFile.standardOutputHasMoved(from: file) { reopenStandardOutput(at: file) }
    }
}

private var logging = Logging()
private let logLock = NSLock()

/// Sends this program's output to the user's log file, when it is running
/// in the background and not at a terminal.
public func logToUserFile() {
    guard isatty(STDOUT_FILENO) == 0 else { return }
    let file = LogFile.url()
    try? FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
    LogFile.rotateIfLarge(file)
    reopenStandardOutput(at: file)
    logLock.withLock { logging.isWritingToFile = true }
}

private func reopenStandardOutput(at file: URL) {
    freopen(file.path, "a", stdout)
    freopen(file.path, "a", stderr)
    setvbuf(stdout, nil, _IOLBF, 0)
}

/// Writes one line to the log, with the time before it, if the account's
/// log level reaches `level`.
/// - Parameter line: built only if it is going to be written, so a line for
///   a level that is off costs nothing to make.
public func log(_ level: LogLevel, _ line: @autoclosure () -> String) {
    logLock.lock()
    defer { logLock.unlock() }
    let now = Date()
    guard level != .none, level <= logging.currentLevel(now: now) else { return }
    logging.keepFileBounded()
    print("\(logging.timestamps.string(from: now)) \(line())")
}

/// Writes one line at the standard level: something an owner needs to know.
public func log(_ line: @autoclosure () -> String) {
    log(.terse, line())
}
