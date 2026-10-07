import EventKit
import Foundation
import RetrieverSourceKit

/// The events of one day, from the Calendar app.
///
/// Which day, and which calendar, are parameters, so that the module can be
/// listed in the module config more than once: as today's events and as
/// tomorrow's, or as one calendar's and as another's.
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
            "calendar": [
                "type": "string", "default": "",
                "description": "The calendar's name as the Calendar app shows it; empty for every calendar.",
            ],
            "days_from_today": [
                "type": "integer", "default": 0, "minimum": .int(-furthestDayFromToday), "maximum": .int(furthestDayFromToday),
                "description": "0 is today, 1 tomorrow, -1 yesterday.",
            ],
        ],
    ]

    /// What a set of parameters asks for, with the defaults for what it leaves out.
    static func asked(by parameters: SourceParameters) -> (calendarName: String, daysFromToday: Int) {
        var calendarName = "", daysFromToday = 0
        if case .string(let name)? = parameters["calendar"] { calendarName = name }
        if case .int(let days)? = parameters["days_from_today"] { daysFromToday = days }
        return (calendarName, daysFromToday)
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
    private func read(_ asked: (calendarName: String, daysFromToday: Int)) -> Entry {
        let calendar = Calendar.current
        guard let day = Self.day(asked.daysFromToday, from: Date(), in: calendar) else { return failed("that day cannot be reckoned") }
        store.refreshSourcesIfNecessary()

        var calendars: [EKCalendar]?   // nil is every calendar
        if !asked.calendarName.isEmpty {
            // Whether a calendar of that name exists can change while the
            // server runs, so it is found out here and not when the server starts.
            let named = store.calendars(for: .event).filter { $0.title.caseInsensitiveCompare(asked.calendarName) == .orderedSame }
            guard !named.isEmpty else { return failed("no calendar named \"\(asked.calendarName)\"") }
            calendars = named
        }

        let onThatDay = store.predicateForEvents(withStart: day.start, end: day.end, calendars: calendars)
        let events = store.events(matching: onThatDay)
            .map { Event(title: $0.title ?? "", calendar: $0.calendar.title, start: $0.startDate, end: $0.endDate, all_day: $0.isAllDay, location: $0.location ?? "") }
            .sorted { ($0.start, $0.title) < ($1.start, $1.title) }
        log(.debug, "Fetched \(events.count) events for \(Self.dateText(of: day.start, in: calendar))")
        return succeeded(Payload(date: Self.dateText(of: day.start, in: calendar), events: events))
    }
}
