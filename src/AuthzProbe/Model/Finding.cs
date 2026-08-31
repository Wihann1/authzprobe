namespace AuthzProbe.Model;

/// <summary>How seriously to treat a finding. <see cref="Error"/> fails the build by default.</summary>
public enum FindingSeverity
{
    /// <summary>Worth knowing about; not a defect on its own.</summary>
    Info,

    /// <summary>A likely defect that needs a human decision about intent.</summary>
    Warning,

    /// <summary>A defect. Fails the build by default.</summary>
    Error
}

/// <summary>Stable identifiers for each rule, so findings can be suppressed individually.</summary>
public static class FindingCodes
{
    /// <summary>Endpoint is reachable without authentication because nothing opted it in.</summary>
    public const string ImplicitlyAnonymous = "AZP001";

    /// <summary>
    /// Endpoint addresses a specific object, requires only "any authenticated user",
    /// and its handler never references the caller — so it cannot be scoping to them.
    /// </summary>
    public const string UnscopedResourceAccess = "AZP002";

    /// <summary>
    /// Endpoint addresses a specific object with no declarative scoping, but its handler
    /// does reference the caller. Possibly correct; needs a human to confirm.
    /// </summary>
    public const string UnverifiedResourceAccess = "AZP005";

    /// <summary>Endpoint is explicitly anonymous and addresses a specific object.</summary>
    public const string AnonymousResourceAccess = "AZP003";

    /// <summary>Endpoint addresses a specific object and is guarded only by a role check.</summary>
    public const string RoleOnlyResourceAccess = "AZP004";
}

/// <summary>A single problem found in the authorization surface.</summary>
public sealed record Finding
{
    /// <summary>Stable rule identifier, e.g. <c>AZP001</c>. See <see cref="FindingCodes"/>.</summary>
    public required string Code { get; init; }

    /// <summary>How seriously to treat this finding.</summary>
    public required FindingSeverity Severity { get; init; }

    /// <summary>One-line statement of the problem.</summary>
    public required string Title { get; init; }

    /// <summary>Why it matters, in enough detail to act on without further context.</summary>
    public required string Detail { get; init; }

    /// <summary>The endpoint this finding relates to, if any.</summary>
    public string? Endpoint { get; init; }

    /// <summary>What to actually do about it.</summary>
    public string? Remediation { get; init; }

    /// <summary>Single-line form, suitable for console and CI output.</summary>
    public override string ToString() =>
        Endpoint is null
            ? $"{Code} [{Severity}] {Title}"
            : $"{Code} [{Severity}] {Endpoint} — {Title}";
}
