import EventKit
import Foundation
import RetrieverSourceKit

/// Today's events and tomorrow's, from the Calendar app.
///
/// Which calendars is a parameter. A calendar is named as the Calendar app
/// shows it, and the name stands for every calendar so called, whichever
/// account it is in.
///
/// A request may also leave out today's events that started some while ago,
/// so that a board shows what is on now and next and not what is over.
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

    /// One day's events.
    struct Day: Codable, Equatable {
        /// The day, as its date in this Mac's time zone: "2026-10-08".
        let date: String
        let count: Int
        let events: [Event]

        init(date: String, events: [Event]) {
            self.date = date
            self.count = events.count
            self.events = events
        }
    }

    struct Payload: Codable, Equatable {
        let today: Day
        let tomorrow: Day
    }

    let name = "calendar"

    /// The shape of `Day`.
    static let daySchema: JSON = [
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

    /// The shape of `Payload`.
    let schema: JSON = [
        "type": "object",
        "properties": ["today": daySchema, "tomorrow": daySchema],
        "default": [
            "today": ["date": "", "count": 0, "events": []],
            "tomorrow": ["date": "", "count": 0, "events": []],
        ],
    ]

    let parametersSchema: JSON = [
        "type": "object",
        "properties": [
            "calendars": [
                "type": "string", "default": "",
                "description": "Only these calendars, by the names the Calendar app shows, separated by commas; empty for every calendar.",
            ],
            "started_after": [
                "type": "string", "format": "date-time", "requestOnly": true,
                "description": "Leave out today's events that started before this moment, written with its offset from UTC, as 2026-11-13T09:15:00-08:00; all-day events stay, and so do tomorrow's. In the plugin's request body, an hour ago is {{= DATEADD(NOW(), -1, \"hours\") }}.",
            ],
        ],
    ]

    /// Which calendars are wanted, each by name.
    enum Wanted: Equatable {
        case every
        case only([String])
    }

    /// The calendars a choice comes to, or the names it gives that no calendar has.
    enum Chosen<Item> {
        case every
        case these([Item])
        case missing([String])
    }

    /// What one fetch is asked for.
    struct Asked: Equatable {
        let wanted: Wanted
        /// The moment before which a timed event today that started is left out; nil to leave none out.
        let startedAfter: Date?
    }

    /// What a set of parameters asks for, with the defaults for what it leaves out.
    static func asked(by parameters: SourceParameters) -> Asked {
        var only: [String] = [], startedAfter: Date?
        if case .string(let list)? = parameters["calendars"] { only = names(in: list) }
        if case .string(let text)? = parameters["started_after"] { startedAfter = moment(from: text) }
        return Asked(wanted: only.isEmpty ? .every : .only(only), startedAfter: startedAfter)
    }

    /// A moment written as in RFC 3339, "2026-11-13T09:15:00-08:00" or
    /// "...Z"; nil without its offset from UTC, which would leave the moment
    /// to be guessed from this Mac's time zone.
    static func moment(from text: String) -> Date? {
        ISO8601DateFormatter().date(from: text)
    }

    /// The events left once those that started before `startedAfter` are
    /// left out. One that started at that moment stays, and so does every
    /// all-day event, which starts at midnight but is not over until the
    /// day is.
    static func events(_ events: [Event], startedAfter: Date?) -> [Event] {
        guard let startedAfter else { return events }
        return events.filter { $0.all_day || $0.start >= startedAfter }
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
    /// no calendar's is a mistake, so that a calendar renamed or misspelt
    /// does not go unnoticed.
    static func choose<Item>(_ wanted: Wanted, from all: [Item], title: (Item) -> String) -> Chosen<Item> {
        guard case .only(let named) = wanted else { return .every }
        let missing = named.filter { name in !all.contains { same(title($0), name) } }
        guard missing.isEmpty else { return .missing(missing) }
        return .these(all.filter { item in named.contains { same(title(item), $0) } })
    }

    func problem(with parameters: SourceParameters) -> String? {
        if let problem = ParametersSchema.problem(with: parameters, against: parametersSchema) { return problem }
        if case .string(let list)? = parameters["calendars"], !list.isEmpty, Self.names(in: list).isEmpty {
            return "the parameter \"calendars\" names no calendar"
        }
        if case .string(let text)? = parameters["started_after"], Self.moment(from: text) == nil {
            return "the parameter \"started_after\" must be a moment with its offset from UTC, as 2026-11-13T09:15:00-08:00, not \"\(text)\""
        }
        return nil
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

    /// Reads today's and tomorrow's events, access having been granted.
    private func read(_ asked: Asked) -> Entry {
        let calendar = Calendar.current
        let now = Date()
        guard let today = Self.day(0, from: now, in: calendar), let tomorrow = Self.day(1, from: now, in: calendar) else {
            return failed("today or tomorrow cannot be reckoned")
        }
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
        let todaysEvents = Self.events(events(on: today, in: calendars), startedAfter: asked.startedAfter)
        let payload = Payload(today: Day(date: Self.dateText(of: today.start, in: calendar), events: todaysEvents),
                              tomorrow: Day(date: Self.dateText(of: tomorrow.start, in: calendar), events: events(on: tomorrow, in: calendars)))
        log(.debug, "Fetched \(payload.today.count) events for today and \(payload.tomorrow.count) for tomorrow")
        return succeeded(payload)
    }

    /// The events of these calendars (nil for every calendar) that fall in
    /// `day`, earliest first.
    private func events(on day: DateInterval, in calendars: [EKCalendar]?) -> [Event] {
        // Asked for the events of no calendars, EventKit gives those of all of them.
        if let calendars, calendars.isEmpty { return [] }
        let onThatDay = store.predicateForEvents(withStart: day.start, end: day.end, calendars: calendars)
        return store.events(matching: onThatDay)
            .map { Event(title: $0.title ?? "", calendar: $0.calendar.title, start: $0.startDate, end: $0.endDate, all_day: $0.isAllDay, location: $0.location ?? "") }
            .sorted { ($0.start, $0.title) < ($1.start, $1.title) }
    }
}
