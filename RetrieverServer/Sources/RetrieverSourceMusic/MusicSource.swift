import Foundation
import RetrieverSourceKit

/// What the Music app on this Mac is playing.
///
/// Only the current track. Music's scripting interface does not expose the
/// Up Next queue, and a track's neighbours in its playlist turned out not to
/// be the tracks played before and after it, even for an album in order.
final class MusicSource: Source {
    /// What is playing.
    struct Payload: Codable, Equatable {
        var state = "stopped"   // "playing", "paused" or "stopped"
        var title = ""
        var artist = ""
        var album = ""
    }

    let name = "music"

    /// The shape of `Payload`.
    let schema: JSON = [
        "type": "object",
        "properties": [
            "state": ["type": "string", "enum": ["playing", "paused", "stopped"]],
            "title": ["type": "string"],
            "artist": ["type": "string"],
            "album": ["type": "string"],
        ],
        "default": ["state": "stopped", "title": "", "artist": "", "album": ""],
    ]

    static let timeout: TimeInterval = 2.5

    // JavaScript for Automation. Prints a Payload as JSON. Asking whether
    // Music is running does not launch it and needs no permission.
    static let script = """
    function run() {
        const out = {state: "stopped", title: "", artist: "", album: ""};
        const music = Application("Music");
        if (!music.running()) return JSON.stringify(out);
        const state = music.playerState();
        if (state === "stopped") return JSON.stringify(out);
        out.state = state === "paused" ? "paused" : "playing";
        try {
            const track = music.currentTrack;
            out.title = track.name();
            out.artist = track.artist();
            out.album = track.album();
        } catch (e) {}
        return JSON.stringify(out);
    }
    """

    func fetch(parameters: SourceParameters, _ done: @escaping (Entry) -> Void) {
        DispatchQueue.global().async {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-l", "JavaScript", "-e", Self.script]
            let output = Pipe(), errors = Pipe()
            process.standardOutput = output
            process.standardError = errors
            do { try process.run() } catch {
                log("osascript could not be run: \(error)")
                return done(self.failed("osascript could not be run"))
            }
            // A question from macOS about controlling Music keeps the script
            // waiting; give up rather than hold the response.
            let deadline = DispatchWorkItem { process.terminate() }
            DispatchQueue.global().asyncAfter(deadline: .now() + Self.timeout, execute: deadline)
            let out = output.fileHandleForReading.readDataToEndOfFile()
            let err = errors.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            deadline.cancel()
            let entry = self.entry(status: process.terminationStatus,
                                   terminated: process.terminationReason == .uncaughtSignal,
                                   output: out, errors: String(decoding: err, as: UTF8.self))
            if !entry.error.isEmpty { log("Music: \(entry.error)") }
            done(entry)
        }
    }

    /// The entry for one run of the script.
    func entry(status: Int32, terminated: Bool, output: Data, errors: String) -> Entry {
        if terminated { return failed("Music did not answer") }
        // -1743: the user has not allowed this program to control Music.
        if errors.contains("-1743") { return failed("not allowed to control Music") }
        guard status == 0, let payload = try? JSONDecoder().decode(Payload.self, from: output) else {
            return failed("Music could not be read")
        }
        return succeeded(payload)
    }
}
