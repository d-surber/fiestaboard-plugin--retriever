import Foundation

/// Checks a set of parameters against the JSON Schema a source declares for them.
///
/// Only as much of JSON Schema as a parameter needs: an object's
/// `properties` and `required`, and for each property its `type` (string,
/// integer, number or boolean), `minimum`, `maximum` and `enum`. A
/// property's `description` and `default` are for telling a person about it.
public enum ParametersSchema {
    /// What is wrong with `parameters`, or nil if they fit `schema`: the
    /// first parameter the schema does not have, has with another type, or
    /// gives a value it does not allow, or the first one it requires that
    /// is missing. In words for the person who wrote the config.
    public static func problem(with parameters: SourceParameters, against schema: JSON) -> String? {
        guard case .object(let object) = schema, case .object(let properties)? = object["properties"] else {
            return parameters.isEmpty ? nil : "takes no parameters"
        }
        for (name, value) in parameters.sorted(by: { $0.key < $1.key }) {
            guard case .object(let property)? = properties[name] else {
                let known = properties.keys.sorted().joined(separator: ", ")
                return "takes no parameter named \"\(name)\"" + (known.isEmpty ? "" : " (it takes: \(known))")
            }
            if let problem = problem(with: value, named: name, against: property) { return problem }
        }
        if case .array(let required)? = object["required"] {
            for case .string(let name) in required where parameters[name] == nil { return "needs the parameter \"\(name)\"" }
        }
        return nil
    }

    /// The parameters `schema` declares, one line each in name order, for
    /// the person writing a config: what kind of value it takes, the limits
    /// on it, whether it must be given or what it is when it is not, and the
    /// schema's own description of it. Empty if the source takes none.
    public static func summary(of schema: JSON) -> [String] {
        guard case .object(let object) = schema, case .object(let properties)? = object["properties"] else { return [] }
        var required: Set<String> = []
        if case .array(let names)? = object["required"] {
            for case .string(let name) in names { required.insert(name) }
        }
        return properties.sorted { $0.key < $1.key }.map { name, declared in
            guard case .object(let property) = declared else { return name }
            var facts: [String] = []
            if case .array(let allowed)? = property["enum"] {
                facts.append("one of " + allowed.map(written).joined(separator: ", "))
            } else if case .string(let type)? = property["type"] {
                facts.append(description(ofType: type))
            }
            if let minimum = property["minimum"] { facts.append("at least \(written(minimum))") }
            if let maximum = property["maximum"] { facts.append("at most \(written(maximum))") }
            if required.contains(name) {
                facts.append("required")
            } else if let value = property["default"] {
                facts.append("\(written(value)) if left out")
            }
            var line = name + (facts.isEmpty ? "" : ": " + facts.joined(separator: ", "))
            if case .string(let explanation)? = property["description"], !explanation.isEmpty { line += ". " + explanation }
            return line
        }
    }

    private static func problem(with value: JSON, named name: String, against property: [String: JSON]) -> String? {
        if case .string(let type)? = property["type"], !isOfType(value, type) {
            return "the parameter \"\(name)\" must be \(description(ofType: type)), not \(written(value))"
        }
        if let number = number(value) {
            if let minimum = property["minimum"].flatMap(number(_:)), number < minimum {
                return "the parameter \"\(name)\" must be at least \(written(property["minimum"] ?? .null)), not \(written(value))"
            }
            if let maximum = property["maximum"].flatMap(self.number(_:)), number > maximum {
                return "the parameter \"\(name)\" must be at most \(written(property["maximum"] ?? .null)), not \(written(value))"
            }
        }
        if case .array(let allowed)? = property["enum"], !allowed.contains(value) {
            return "the parameter \"\(name)\" must be one of \(allowed.map(written).joined(separator: ", ")), not \(written(value))"
        }
        return nil
    }

    private static func isOfType(_ value: JSON, _ type: String) -> Bool {
        switch (type, value) {
        case ("string", .string), ("integer", .int), ("number", .int), ("number", .double), ("boolean", .bool): return true
        case ("string", _), ("integer", _), ("number", _), ("boolean", _): return false
        default: return true   // a type this does not know is not checked
        }
    }

    private static func description(ofType type: String) -> String {
        ["string": "text", "integer": "a whole number", "number": "a number", "boolean": "true or false"][type] ?? type
    }

    private static func number(_ value: JSON) -> Double? {
        switch value {
        case .int(let whole): return Double(whole)
        case .double(let number): return number
        default: return nil
        }
    }

    /// A value as a person would write it in a config.
    private static func written(_ value: JSON) -> String {
        (try? JSONEncoder().encode(value)).map { String(decoding: $0, as: UTF8.self) } ?? "?"
    }
}
