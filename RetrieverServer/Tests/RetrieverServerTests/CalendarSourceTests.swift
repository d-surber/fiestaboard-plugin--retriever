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

@Test func aDaysEventsFitTheSchema() throws {
    let event = CalendarSource.Event(title: "Dentist", calendar: "Home", start: moment(2026, 10, 8, 9), end: moment(2026, 10, 8, 10), all_day: false, location: "")
    let payload = CalendarSource.Payload(date: "2026-10-08", events: [event])
    #expect(payload.count == 1)
    #expect(matches(try #require(JSON(encoding: payload)), CalendarSource().schema))
}

@Test func itSaysWhatItsParametersAreFor() {
    #expect(ParametersSchema.summary(of: CalendarSource().parametersSchema) == [
        "calendars: text, \"\" if left out. Only these calendars, by the names the Calendar app shows, separated by commas; empty for every calendar.",
        "days_from_today: a whole number, at least -3660, at most 3660, 0 if left out. 0 is today, 1 tomorrow, -1 yesterday.",
        "except: text, \"\" if left out. Every calendar but these, named the same way. Not together with calendars.",
    ])
}

@Test func withNoParametersItIsEveryCalendarToday() {
    let asked = CalendarSource.asked(by: [:])
    #expect(asked.wanted == .every)
    #expect(asked.daysFromToday == 0)
}

@Test func itIsAskedForCalendarsByNameAndADayByItsDistanceFromToday() {
    let asked = CalendarSource.asked(by: ["calendars": "Work, Family", "days_from_today": -1])
    #expect(asked.wanted == .only(["Work", "Family"]))
    #expect(asked.daysFromToday == -1)
}

@Test func itIsAskedForEveryCalendarButSome() {
    #expect(CalendarSource.asked(by: ["except": "Birthdays,US Holidays"]).wanted == .allBut(["Birthdays", "US Holidays"]))
    #expect(CalendarSource.asked(by: ["calendars": "", "except": ""]).wanted == .every)
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

@Test func everyCalendarButTheNamedOnesIsChosen() {
    #expect(chosen(.allBut(["Birthdays"])) == "these [0, 1, 3, 4]")
    #expect(chosen(.allBut(["home"])) == "these [1, 2, 4]")
    #expect(chosen(.allBut(["Home", "Work", "Birthdays", "Family"])) == "these []")
}

@Test func aNameThatIsNoCalendarsIsAMistakeWhicheverListItIsIn() {
    #expect(chosen(.only(["Work", "Wrok", "Holidays"])) == "missing [\"Wrok\", \"Holidays\"]")
    #expect(chosen(.allBut(["Birthdays", "Holidays"])) == "missing [\"Holidays\"]")
}

@Test(arguments: [
    (["calendars": "Work, Family", "days_from_today": 1] as SourceParameters, nil as String?),
    (["except": "Birthdays"], nil),
    (["calendars": "", "except": "Birthdays"], nil),
    (["calendars": "Work", "except": "Birthdays"], "give \"calendars\" or \"except\", not both"),
    (["calendars": " , "], "the parameter \"calendars\" names no calendar"),
    (["except": ","], "the parameter \"except\" names no calendar"),
    (["days_from_today": "tomorrow"], "the parameter \"days_from_today\" must be a whole number, not \"tomorrow\""),
    (["days_from_today": .double(0.5)], "the parameter \"days_from_today\" must be a whole number, not 0.5"),
    (["days_from_today": 4000], "the parameter \"days_from_today\" must be at most 3660, not 4000"),
    (["calendars": 7], "the parameter \"calendars\" must be text, not 7"),
    (["calendar": "Work"], "takes no parameter named \"calendar\" (it takes: calendars, days_from_today, except)"),
    (["date": "2026-10-08"], "takes no parameter named \"date\" (it takes: calendars, days_from_today, except)"),
])
func itsParametersAreChecked(parameters: SourceParameters, problem: String?) {
    #expect(CalendarSource().problem(with: parameters) == problem)
}

@Test(arguments: [(0, "2026-10-08"), (1, "2026-10-09"), (-1, "2026-10-07"), (24, "2026-11-01"), (-8, "2026-09-30"), (365, "2027-10-08")])
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
