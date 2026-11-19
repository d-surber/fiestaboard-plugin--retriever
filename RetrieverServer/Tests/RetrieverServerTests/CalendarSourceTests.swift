import Foundation
import Testing
@testable import RetrieverSourceCalendar
@testable import RetrieverSourceKit

/// A calendar that reckons days as Los Angeles does, where a day may have 23 or 25 hours.
private var losAngeles: Calendar {
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(identifier: "America/Los_Angeles")!
    return calendar
}

/// A moment in Los Angeles, from its date and time there.
private func moment(_ year: Int, _ month: Int, _ day: Int, _ hour: Int = 12) -> Date {
    losAngeles.date(from: DateComponents(year: year, month: month, day: day, hour: hour))!
}

@Test func calendarFitsTheSourceContract() {
    #expect(fitsTheSourceContract(CalendarSource()))
}

@Test func todaysAndTomorrowsEventsFitTheSchema() throws {
    let event = CalendarSource.Event(title: "Dentist", calendar: "Home", start: moment(2026, 10, 8, 9), end: moment(2026, 10, 8, 10), all_day: false, location: "")
    let payload = CalendarSource.Payload(today: CalendarSource.Day(date: "2026-10-08", events: [event]),
                                         tomorrow: CalendarSource.Day(date: "2026-10-09", events: []))
    #expect(payload.today.count == 1)
    #expect(payload.tomorrow.count == 0)
    #expect(matches(try #require(JSON(encoding: payload)), CalendarSource().schema))
}

@Test func whenItCannotBeReadItGivesTwoEmptyDays() {
    #expect(CalendarSource().failed("Calendar access denied").data == [
        "today": ["date": "", "count": 0, "events": []],
        "tomorrow": ["date": "", "count": 0, "events": []],
    ])
}

@Test func itSaysWhatItsParametersAreFor() {
    #expect(ParametersSchema.summary(of: CalendarSource().parametersSchema) == [
        "calendars: text, \"\" if left out. Only these calendars, by the names the Calendar app shows, separated by commas; empty for every calendar.",
        "started_after: text, set only by a request. Leave out today's events that started before this moment, written with its offset from UTC, as 2026-11-13T09:15:00-08:00; all-day events stay, and so do tomorrow's. In the plugin's request body, an hour ago is {{= DATEADD(NOW(), -1, \"hours\") }}.",
    ])
}

@Test func withNoParametersItIsEveryCalendar() {
    let asked = CalendarSource.asked(by: [:])
    #expect(asked.wanted == .every)
    #expect(asked.startedAfter == nil)
    #expect(CalendarSource.asked(by: ["calendars": ""]).wanted == .every)
}

@Test func itIsAskedForCalendarsByName() {
    #expect(CalendarSource.asked(by: ["calendars": "Work, Family"]).wanted == .only(["Work", "Family"]))
}

@Test(arguments: [
    ("Work", ["Work"]),
    ("Work,Family", ["Work", "Family"]),
    ("  Work ,  US Holidays  ", ["Work", "US Holidays"]),
    ("Work,,Family,", ["Work", "Family"]),
    ("Work, work, WORK, Family", ["Work", "Family"]),
    ("", []),
    (" , ", []),
])
func aListOfNamesIsWrittenWithCommas(list: String, names: [String]) {
    #expect(CalendarSource.names(in: list) == names)
}

/// The calendars of a Mac with two accounts, each with a calendar called Home.
private let calendarsHere = ["Home", "Work", "Birthdays", "Home", "Family"]

private func chosen(_ wanted: CalendarSource.Wanted) -> String {
    switch CalendarSource.choose(wanted, from: Array(calendarsHere.indices), title: { calendarsHere[$0] }) {
    case .every: return "every"
    case .these(let indices): return "these \(indices)"
    case .missing(let names): return "missing \(names)"
    }
}

@Test func onlyTheNamedCalendarsAreChosenInWhicheverAccountTheyAre() {
    #expect(chosen(.every) == "every")
    #expect(chosen(.only(["Work"])) == "these [1]")
    #expect(chosen(.only(["home", "FAMILY"])) == "these [0, 3, 4]")
}

@Test func aNameThatIsNoCalendarsIsAMistake() {
    #expect(chosen(.only(["Work", "Wrok", "Holidays"])) == "missing [\"Wrok\", \"Holidays\"]")
}

@Test(arguments: [
    (["calendars": "Work, Family"] as SourceParameters, nil as String?),
    (["calendars": ""], nil),
    (["calendars": " , "], "the parameter \"calendars\" names no calendar"),
    (["calendars": 7], "the parameter \"calendars\" must be text, not 7"),
    (["calendar": "Work"], "takes no parameter named \"calendar\" (it takes: calendars, started_after)"),
    (["except": "Birthdays"], "takes no parameter named \"except\" (it takes: calendars, started_after)"),
    (["days_from_today": 1], "takes no parameter named \"days_from_today\" (it takes: calendars, started_after)"),
])
func itsParametersAreChecked(parameters: SourceParameters, problem: String?) {
    #expect(CalendarSource().problem(with: parameters) == problem)
}

@Test(arguments: [(0, "2026-10-08"), (1, "2026-10-09"), (24, "2026-11-01"), (365, "2027-10-08")])
func aDayIsCountedFromToday(daysFromToday: Int, date: String) throws {
    let day = try #require(CalendarSource.day(daysFromToday, from: moment(2026, 10, 8, 15), in: losAngeles))
    #expect(CalendarSource.dateText(of: day.start, in: losAngeles) == date)
    #expect(losAngeles.component(.hour, from: day.start) == 0)
}

@Test func aDayRunsFromItsFirstMomentToTheNextDaysWhateverTheTimeNow() throws {
    let early = try #require(CalendarSource.day(0, from: moment(2026, 10, 8, 0), in: losAngeles))
    let late = try #require(CalendarSource.day(0, from: moment(2026, 10, 8, 23), in: losAngeles))
    #expect(early == late)
    #expect(early.start == moment(2026, 10, 8, 0))
    #expect(early.end == moment(2026, 10, 9, 0))
}

@Test func aDayIsADayEvenWhenTheClocksChange() throws {
    // In Los Angeles 1 November 2026 has 25 hours and 8 March 2026 has 23.
    let long = try #require(CalendarSource.day(0, from: moment(2026, 11, 1), in: losAngeles))
    #expect(long.duration == 25 * 3600)
    let short = try #require(CalendarSource.day(1, from: moment(2026, 3, 7), in: losAngeles))
    #expect(short.duration == 23 * 3600)
    #expect(CalendarSource.dateText(of: short.start, in: losAngeles) == "2026-03-08")
}

@Test func aRequestCanSayWhenTheEventsItWantsStarted() {
    // As the plugin sends it: an hour before 10:15 in Los Angeles.
    let asked = CalendarSource.asked(by: ["started_after": "2026-11-13T09:15:00-08:00"])
    #expect(asked.startedAfter == moment(2026, 11, 13, 9).addingTimeInterval(15 * 60))
    #expect(CalendarSource.asked(by: ["started_after": "2026-11-13T17:15:00Z"]).startedAfter == asked.startedAfter)
}

@Test(arguments: [
    ("2026-11-13T09:15:00-08:00", true),
    ("2026-11-13T17:15:00Z", true),
    ("2026-11-13T09:15:00", false),
    ("2026-11-13", false),
    ("an hour ago", false),
])
func whenTheEventsStartedIsAMomentWithItsOffsetFromUTC(text: String, taken: Bool) {
    let problem = "the parameter \"started_after\" must be a moment with its offset from UTC, as 2026-11-13T09:15:00-08:00, not \"\(text)\""
    #expect(CalendarSource().problem(with: ["started_after": .string(text)]) == (taken ? nil : problem))
}

@Test func onlyARequestMaySayWhenTheEventsStarted() {
    #expect(ParametersSchema.requestOnly(in: CalendarSource().parametersSchema) == ["started_after"])
}

/// A timed event on 13 November 2026 in Los Angeles, from its hours there.
private func timed(_ title: String, from startHour: Int, to endHour: Int) -> CalendarSource.Event {
    CalendarSource.Event(title: title, calendar: "Home", start: moment(2026, 11, 13, startHour), end: moment(2026, 11, 13, endHour), all_day: false, location: "")
}

private let holiday = CalendarSource.Event(title: "Holiday", calendar: "Home", start: moment(2026, 11, 13, 0), end: moment(2026, 11, 14, 0), all_day: true, location: "")

@Test func eventsThatStartedBeforeTheMomentAreLeftOutButAllDayEventsStay() {
    let day = [holiday, timed("Breakfast", from: 7, to: 8), timed("Meeting", from: 9, to: 11), timed("Lunch", from: 12, to: 13)]
    let titles = CalendarSource.events(day, startedAfter: moment(2026, 11, 13, 9)).map(\.title)
    // Meeting started at the moment itself, and stays.
    #expect(titles == ["Holiday", "Meeting", "Lunch"])
}

@Test func withNoMomentNoEventIsLeftOut() {
    let day = [holiday, timed("Breakfast", from: 7, to: 8)]
    #expect(CalendarSource.events(day, startedAfter: nil) == day)
}
