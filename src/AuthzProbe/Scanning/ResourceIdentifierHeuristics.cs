using System.Text.RegularExpressions;

namespace AuthzProbe.Scanning;

/// <summary>
/// Decides whether a route parameter addresses a specific stored object.
/// This is the signal that separates "an endpoint" from "an endpoint an attacker
/// can point at someone else's row".
/// </summary>
public static partial class ResourceIdentifierHeuristics
{
    private static readonly string[] ExactNames =
    [
        "id", "key", "guid", "uuid", "ref", "reference", "number", "no", "code", "slug", "handle"
    ];

    private static readonly string[] Suffixes =
    [
        "id", "guid", "uuid", "key", "ref", "number", "code"
    ];

    /// <summary>
    /// Parameters that look like identifiers but address a <em>type</em> of thing rather than
    /// one owned instance, so they carry no object-ownership risk on their own.
    /// </summary>
    private static readonly string[] NonResourceNames =
    [
        "version", "apiversion", "culture", "lang", "language", "locale",
        "page", "pagesize", "skip", "take", "offset", "limit", "count",
        "format", "type", "kind", "status", "sort", "order", "filter", "query", "search"
    ];

    /// <summary>
    /// True when <paramref name="parameterName"/> plausibly identifies a specific stored object.
    /// </summary>
    public static bool LooksLikeResourceIdentifier(string parameterName)
    {
        if (string.IsNullOrWhiteSpace(parameterName))
        {
            return false;
        }

        var normalised = Normalise(parameterName);

        if (NonResourceNames.Contains(normalised))
        {
            return false;
        }

        if (ExactNames.Contains(normalised))
        {
            return true;
        }

        // userId, invoiceGuid, tenantKey, orderNumber…
        return Suffixes.Any(suffix =>
            normalised.Length > suffix.Length && normalised.EndsWith(suffix, StringComparison.Ordinal));
    }

    /// <summary>Extracts parameter names from a route template, dropping constraints and defaults.</summary>
    public static IReadOnlyList<string> ExtractRouteParameters(string? routePattern)
    {
        if (string.IsNullOrWhiteSpace(routePattern))
        {
            return [];
        }

        var names = new List<string>();

        foreach (Match match in RouteParameterRegex().Matches(routePattern))
        {
            var raw = match.Groups[1].Value;

            // "id:guid", "id=5", "*catchAll", "id?" -> "id"
            var name = raw
                .Split(':', 2)[0]
                .Split('=', 2)[0]
                .TrimStart('*')
                .TrimEnd('?')
                .Trim();

            if (name.Length > 0)
            {
                names.Add(name);
            }
        }

        return names;
    }

    private static string Normalise(string value) =>
        new(value.Where(char.IsLetterOrDigit).Select(char.ToLowerInvariant).ToArray());

    [GeneratedRegex(@"\{([^}]+)\}", RegexOptions.CultureInvariant)]
    private static partial Regex RouteParameterRegex();
}
