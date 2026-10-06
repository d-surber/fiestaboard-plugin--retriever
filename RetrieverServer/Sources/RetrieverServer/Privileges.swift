import Foundation

/// The account a command run with `sudo` was run from.
struct InvokingAccount {
    let name: String
    let uid: uid_t
    let gid: gid_t
    let home: URL

    /// The account named by `SUDO_USER`, or nil if there is none or it is unknown.
    static func fromSudo(environment: [String: String] = ProcessInfo.processInfo.environment) -> InvokingAccount? {
        guard let name = environment["SUDO_USER"], let entry = getpwnam(name) else { return nil }
        return InvokingAccount(name: name, uid: entry.pointee.pw_uid, gid: entry.pointee.pw_gid,
                               home: URL(fileURLWithPath: String(cString: entry.pointee.pw_dir), isDirectory: true))
    }

    /// Does `work` with this account's access to files and no more.
    ///
    /// A command running as root must not act as root on a path the account
    /// controls: a link planted there would turn the command's reach into
    /// the account's. Whatever touches the account's own folder is done
    /// through here, where the worst a planted link can do is what the
    /// account could have done itself.
    ///
    /// When the program is not running as root there is nothing to give up,
    /// and `work` simply runs.
    /// - Throws: `PrivilegeError` if the account's identity cannot be taken on, or whatever `work` throws.
    func withItsAccess<Result>(_ work: () throws -> Result) throws -> Result {
        guard geteuid() == 0 else { return try work() }
        var rootGroups = [gid_t](repeating: 0, count: Int(max(getgroups(0, nil), 0)))
        let groupCount = getgroups(Int32(rootGroups.count), &rootGroups)
        var ownGroup = [gid]
        guard groupCount >= 0, setgroups(1, &ownGroup) == 0, setegid(gid) == 0, seteuid(uid) == 0 else {
            _ = seteuid(0)
            _ = setegid(0)
            throw PrivilegeError()
        }
        defer {
            // Going back cannot be allowed to fail quietly: what follows expects to be root.
            precondition(seteuid(0) == 0 && setegid(0) == 0 && setgroups(groupCount, &rootGroups) == 0,
                         "could not return to root")
        }
        return try work()
    }
}

struct PrivilegeError: Error, CustomStringConvertible {
    let description = "could not act as the account that ran sudo"
}
