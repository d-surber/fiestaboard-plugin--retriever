import EventKit
import Foundation
import RetrieverSourceKit

/// The events of one day, from the Calendar app.
///
/// Which day, and which calendars, are parameters, so that the module can be
/// listed in the module config more than once: as today's events and as
/// tomorrow's, or as some calendars' and as others'.
///
/// A calendar is named as the Calendar app shows it, and the name stands for
/// every calendar so called, whichever account it is in.
final class CalendarSource: Source {
    /// One event. Times are moments, not text laid out for a display.
    struct Event: Codable, Equatable {
        let title: String
        let calendar: String
        let start: Date
        let end: Date
        let all_day: Bool
        let location: String
    }

    struct Payload: Codable, Equatable {
        /// The day asked for, as its date in this Mac's time zone: "2026-10-08".
        let date: String
        let count: Int
        let events: [Event]

        init(date: String, events: [Event]) {
            self.date = date
            self.count = events.count
            self.events = events
        }
    }

    let name = "calendar"

    /// The shape of `Payload`.
    let schema: JSON = [
        "type": "object",
        "properties": [
            "date": ["type": "string", "format": "date"],
            "count": ["type": "integer"],
            "events": [
                "type": "array",
                "items": [
                    "type": "object",
                    "properties": [
                        "title": ["type": "string"],
                        "calendar": ["type": "string"],
                        "start": ["type": "string", "format": "date-time"],
                        "end": ["type": "string", "format": "date-time"],
                        "all_day": ["type": "boolean"],
                        "location": ["type": "string"],
                    ],
                ],
            ],
        ],
        "default": ["date": "", "count": 0, "events": []],
    ]

    /// How far from today a day may be asked for, either way: ten years.
    static let furthestDayFromToday = 3660

    let parametersSchema: JSON = [
        "type": "object",
        "properties": [
            "calendars": [
                "type": "string", "default": "",
                "description": "Only these calendars, by the names the Calendar app shows, separated by commas; empty for every calendar.",
            ],
            "days_from_today": [
                "type": "integer", "default": 0, "minimum": .int(-furthestDayFromToday), "maximum": .int(furthestDayFromToday),
                "description": "0 is today, 1 tomorrow, -1 yesterday.",
            ],
            "except": [
                "type": "string", "default": "",
                "description": "Every calendar but these, named the same way. Not together with calendars.",
            ],
        ],
    ]

    /// Which calendars are wanted, each by name.
    enum Wanted: Equatable {
        case every
        case only([String])
        case allBut([String])
    }

    /// The calendars a choice comes to, or the names it gives that no calendar has.
    enum Chosen<Item> {
        case every
        case these([Item])
        case missing([String])
    }

    /// What a set of parameters asks for, with the defaults for what it leaves out.
    static func asked(by parameters: SourceParameters) -> (wanted: Wanted, daysFromToday: Int) {
        var only: [String] = [], allBut: [String] = [], daysFromToday = 0
        if case .string(let list)? = parameters["calendars"] { only = names(in: list) }
        if case .string(let list)? = parameters["except"] { allBut = names(in: list) }
        if case .int(let days)? = parameters["days_from_today"] { daysFromToday = days }
        // Both lists at once does not pass `problem(with:)`.
        return (!only.isEmpty ? .only(only) : !allBut.isEmpty ? .allBut(allBut) : .every, daysFromToday)
    }

    /// The names in a list written with commas between them: without the
    /// space around each, and each once however it is capitalised.
    static func names(in list: String) -> [String] {
        var names: [String] = []
        for name in list.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) where !name.isEmpty {
            if !names.contains(where: { same($0, name) }) { names.append(name) }
        }
        return names
    }

    /// Whether two names name the same calendar: capitals do not matter.
    static func same(_ one: String, _ other: String) -> Bool {
        one.caseInsensitiveCompare(other) == .orderedSame
    }

    /// Which of `all` are wanted, going by the title of each. A name that is
    /// no calendar's is a mistake whether it was to be read or left out, so
    /// that a calendar renamed or misspelt does not go unnoticed.
    static func choose<Item>(_ wanted: Wanted, from all: [Item], title: (Item) -> String) -> Chosen<Item> {
        let named: [String]
        switch wanted {
        case .every: return .every
        case .only(let names), .allBut(let names): named = names
        }
        let missing = named.filter { name in !all.contains { same(title($0), name) } }
        guard missing.isEmpty else { return .missing(missing) }
        var only = false
        if case .only = wanted { only = true }
        return .these(all.filter { item in named.contains { same(title(item), $0) } == only })
    }

    func problem(with parameters: SourceParameters) -> String? {
        if let problem = ParametersSchema.problem(with: parameters, against: parametersSchema) { return problem }
        var listed: [String] = []
        for parameter in ["calendars", "except"] {
            guard case .string(let list)? = parameters[parameter], !list.isEmpty else { continue }
            if Self.names(in: list).isEmpty { return "the parameter \"\(parameter)\" names no calendar" }
            listed.append(parameter)
        }
        return listed.count > 1 ? "give \"calendars\" or \"except\", not both" : nil
    }

    /// The day that is `daysFromToday` after the day `now` falls in, from its
    /// first moment to the first moment of the day after, as `calendar`
    /// reckons days. Nil only for a date the calendar cannot reach.
    static func day(_ daysFromToday: Int, from now: Date, in calendar: Calendar) -> DateInterval? {
        guard let start = calendar.date(byAdding: .day, value: daysFromToday, to: calendar.startOfDay(for: now)),
              let end = calendar.date(byAdding: .day, value: 1, to: start) else { return nil }
        return DateInterval(start: start, end: end)
    }

    /// A day's date as year, month and day in `calendar`'s time zone: "2026-10-08".
    static func dateText(of day: Date, in calendar: Calendar) -> String {
        let parts = calendar.dateComponents([.year, .month, .day], from: day)
        return String(format: "%04d-%02d-%02d", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
    }

    private let store = EKEventStore()

    func fetch(parameters: SourceParameters, _ done: @escaping (Entry) -> Void) {
        // Asks the user the first time; answers at once after that.
        store.requestFullAccessToEvents { granted, error in
            guard granted else {
                log("Calendar access denied: \(error?.localizedDescription ?? "no error given")")
                return done(self.failed("Calendar access denied"))
            }
            done(self.read(Self.asked(by: parameters)))
        }
    }

    /// Reads one day's events, access having been granted.
    private func read(_ asked: (wanted: Wanted, daysFromToday: Int)) -> Entry {
        let calendar = Calendar.current
        guard let day = Self.day(asked.daysFromToday, from: Date(), in: calendar) else { return failed("that day cannot be reckoned") }
        store.refreshSourcesIfNecessary()

        // Whether a calendar of a name exists can change while the server
        // runs, so it is found out here and not when the server starts.
        var calendars: [EKCalendar]?   // nil is every calendar
        switch Self.choose(asked.wanted, from: store.calendars(for: .event), title: \.title) {
        case .every: break
        case .these(let chosen): calendars = chosen
        case .missing(let names):
            return failed((names.count == 1 ? "no calendar named " : "no calendars named ") + names.map { "\"\($0)\"" }.joined(separator: ", "))
        }
        // Asked for the events of no calendars, EventKit gives those of all of them.
        if let calendars, calendars.isEmpty {
            return succeeded(Payload(date: Self.dateText(of: day.start, in: calendar), events: []))
        }

        let onThatDay = store.predicateForEvents(withStart: day.start, end: day.end, calendars: calendars)
        let events = store.events(matching: onThatDay)
            .map { Event(title: $0.title ?? "", calendar: $0.calendar.title, start: $0.startDate, end: $0.endDate, all_day: $0.isAllDay, location: $0.location ?? "") }
            .sorted { ($0.start, $0.title) < ($1.start, $1.title) }
        log(.debug, "Fetched \(events.count) events for \(Self.dateText(of: day.start, in: calendar))")
        return succeeded(Payload(date: Self.dateText(of: day.start, in: calendar), events: events))
    }
}
