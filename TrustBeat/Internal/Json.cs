using System.Text;

namespace TrustBeat.Internal;

/// <summary>
/// Minimal zero-dependency JSON parser for TrustBeat API responses.
/// Supports objects, arrays of objects, strings, numbers, booleans, null.
/// </summary>
internal static class Json
{
    // ── Public entry points ────────────────────────────────────────────────────

    internal static Dictionary<string, object?> ParseObject(string json)
    {
        var p = new Parser(json.Trim());
        return (Dictionary<string, object?>)p.ParseValue()!;
    }

    // ── Parser ─────────────────────────────────────────────────────────────────

    private sealed class Parser(string s)
    {
        private int _pos;

        internal object? ParseValue()
        {
            SkipWs();
            if (_pos >= s.Length) throw new InvalidOperationException("Unexpected end of JSON");
            return s[_pos] switch
            {
                '{' => ParseObject(),
                '[' => ParseArray(),
                '"' => ParseString(),
                't' => ParseLiteral("true",  true),
                'f' => ParseLiteral("false", false),
                'n' => ParseLiteral("null",  null),
                _   => ParseNumber()
            };
        }

        private Dictionary<string, object?> ParseObject()
        {
            Expect('{');
            var map = new Dictionary<string, object?>();
            SkipWs();
            if (Peek() == '}') { _pos++; return map; }
            while (true)
            {
                SkipWs();
                var key = ParseString();
                SkipWs(); Expect(':');
                map[key] = ParseValue();
                SkipWs();
                if (s[_pos] == '}') { _pos++; break; }
                if (s[_pos] == ',') { _pos++; continue; }
                throw new InvalidOperationException($"Expected ',' or '}}' at {_pos}");
            }
            return map;
        }

        private List<object?> ParseArray()
        {
            Expect('[');
            var list = new List<object?>();
            SkipWs();
            if (Peek() == ']') { _pos++; return list; }
            while (true)
            {
                list.Add(ParseValue());
                SkipWs();
                if (s[_pos] == ']') { _pos++; break; }
                if (s[_pos] == ',') { _pos++; continue; }
                throw new InvalidOperationException($"Expected ',' or ']' at {_pos}");
            }
            return list;
        }

        private string ParseString()
        {
            Expect('"');
            var sb = new StringBuilder();
            while (_pos < s.Length)
            {
                var c = s[_pos++];
                if (c == '"') return sb.ToString();
                if (c == '\\')
                {
                    var e = s[_pos++];
                    sb.Append(e switch { '"' => '"', '\\' => '\\', '/' => '/',
                                        'n' => '\n', 'r' => '\r',  't' => '\t', _ => e });
                }
                else sb.Append(c);
            }
            throw new InvalidOperationException("Unterminated string");
        }

        private object? ParseLiteral(string token, object? value)
        {
            if (s.AsSpan(_pos).StartsWith(token)) { _pos += token.Length; return value; }
            throw new InvalidOperationException($"Expected '{token}' at {_pos}");
        }

        private object ParseNumber()
        {
            int start = _pos;
            if (_pos < s.Length && s[_pos] == '-') _pos++;
            while (_pos < s.Length && (char.IsDigit(s[_pos]) || s[_pos] is '.' or 'e' or 'E' or '+' or '-'))
                _pos++;
            var num = s[start.._pos];
            return num.Contains('.') || num.Contains('e') || num.Contains('E')
                ? (object)double.Parse(num) : long.Parse(num);
        }

        private void Expect(char c)
        {
            if (_pos >= s.Length || s[_pos] != c)
                throw new InvalidOperationException($"Expected '{c}' at {_pos}");
            _pos++;
        }

        private char Peek() => _pos < s.Length ? s[_pos] : '\0';

        private void SkipWs()
        {
            while (_pos < s.Length && char.IsWhiteSpace(s[_pos])) _pos++;
        }
    }

    // ── Convenience getters ────────────────────────────────────────────────────

    internal static string? Str(Dictionary<string, object?> m, string key)
        => m.TryGetValue(key, out var v) ? v?.ToString() : null;

    internal static bool Bool(Dictionary<string, object?> m, string key, bool def)
        => m.TryGetValue(key, out var v) ? v is bool b ? b : def : def;

    internal static int Int(Dictionary<string, object?> m, string key)
        => m.TryGetValue(key, out var v) && v is long l ? (int)l : 0;

    internal static IEnumerable<Dictionary<string, object?>> Array(
        Dictionary<string, object?> m, string key)
    {
        if (m.TryGetValue(key, out var v) && v is List<object?> list)
            foreach (var item in list)
                if (item is Dictionary<string, object?> d) yield return d;
    }

    // ── Request body builder ───────────────────────────────────────────────────

    /// <summary>Builds a JSON object, omitting null values.</summary>
    internal static string BuildObject(params (string Key, object? Value)[] pairs)
    {
        var sb = new StringBuilder("{");
        bool first = true;
        foreach (var (key, value) in pairs)
        {
            if (value is null) continue;
            if (!first) sb.Append(',');
            first = false;
            sb.Append('"').Append(Escape(key)).Append("\":");
            AppendValue(sb, value);
        }
        return sb.Append('}').ToString();
    }

    private static void AppendValue(StringBuilder sb, object? v)
    {
        switch (v)
        {
            case null:    sb.Append("null");  break;
            case bool b:  sb.Append(b ? "true" : "false"); break;
            case int i:   sb.Append(i);       break;
            case long l:  sb.Append(l);       break;
            case double d: sb.Append(d);      break;
            case RawJson r: sb.Append(r.Value); break;
            default:
                sb.Append('"').Append(Escape(v.ToString()!)).Append('"');
                break;
        }
    }

    private static string Escape(string s)
        => s.Replace("\\", "\\\\").Replace("\"", "\\\"")
            .Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");

    /// <summary>Wraps a pre-serialized JSON fragment to be embedded verbatim.</summary>
    internal sealed class RawJson(string value) { internal string Value => value; }
}
