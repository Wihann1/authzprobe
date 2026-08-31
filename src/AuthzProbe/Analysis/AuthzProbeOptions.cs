using System.Text.RegularExpressions;
using AuthzProbe.Model;

namespace AuthzProbe.Analysis;

/// <summary>Controls which endpoints are analysed and which findings fail a build.</summary>
public sealed class AuthzProbeOptions
{
    /// <summary>
    /// Route patterns that are legitimately public. Supports <c>*</c> as a wildcard,
    /// e.g. <c>"health*"</c>, <c>"swagger/*"</c>.
    /// </summary>
    public IList<string> IgnoredRoutePatterns { get; } = new List<string>
    {
        "health*",
        "healthz*",
        "swagger*",
        "openapi*",
        ".well-known/*",
        "_framework/*",
        "error*"
    };

    /// <summary>Finding codes to suppress entirely.</summary>
    public ISet<string> SuppressedCodes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Minimum severity that causes <see cref="AuthorizationSurfaceReport.ThrowIfFailed"/> to throw.
    /// Defaults to <see cref="FindingSeverity.Error"/>.
    /// </summary>
    public FindingSeverity FailOn { get; set; } = FindingSeverity.Error;

    /// <summary>
    /// When true, an endpoint that addresses a resource but carries only a bare
    /// <c>[Authorize]</c> is treated as an error rather than a warning. Turn this on
    /// once the existing surface is clean, to stop new IDOR-shaped endpoints landing.
    /// </summary>
    public bool TreatUnscopedResourceAccessAsError { get; set; }

    /// <summary>
    /// When true, static-asset and routing-fallback endpoints are analysed too. They serve
    /// files rather than application data, so they are excluded by default.
    /// </summary>
    public bool IncludeInfrastructureEndpoints { get; set; }

    internal bool IsIgnored(string? routePattern)
    {
        if (routePattern is null)
        {
            return false;
        }

        var trimmed = routePattern.TrimStart('/');

        return IgnoredRoutePatterns.Any(pattern =>
        {
            var regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
            return Regex.IsMatch(trimmed, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        });
    }
}
