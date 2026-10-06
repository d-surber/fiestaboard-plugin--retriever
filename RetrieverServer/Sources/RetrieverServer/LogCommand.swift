import Foundation
import RetrieverSourceKit

/// `RetrieverServer log [level]`: show, or choose, how much is written to the log.
enum LogCommand {
    static func run(_ arguments: [String]) -> Never {
        let file = LogSettings.file()
        guard let word = arguments.first else {
            print("Log level: \(LogSettings.level(in: file).rawValue). The log is \(LogFile.url().path).")
            print(levels)
            exit(0)
        }
        guard let level = LogLevel(named: word) else {
            print("\"\(word)\" is not a log level.\n\(levels)")
            exit(2)
        }
        // The choice is the account's own; made with sudo it would be root's, which nothing reads.
        guard getuid() != 0 else {
            print("Choose the log level as yourself, not with sudo.")
            exit(1)
        }
        do { try LogSettings.set(level, in: file) } catch {
            print("The log level could not be recorded: \(error.localizedDescription)")
            exit(1)
        }
        print("Log level: \(level.rawValue). The server and its modules follow within a few seconds.")
        exit(0)
    }

    static let levels = """
        The levels, each including those before it:
          none     nothing
          terse    starting, what is served, and whatever goes wrong (the standard)
          verbose  also each request answered, and how many connections were not
          debug    also each source's answer and how long it took
        """
}
