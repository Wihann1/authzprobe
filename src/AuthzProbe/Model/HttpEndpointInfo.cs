namespace AuthzProbe.Model;

/// <summary>
/// A single routable endpoint in an ASP.NET Core application, together with the
/// authorization metadata attached to it.
/// </summary>
public sealed record HttpEndpointInfo
{
    /// <summary>Framework display name, e.g. <c>HTTP: GET /api/invoices/{id}</c>.</summary>
    public required string DisplayName { get; init; }

    /// <summary>The raw route template, e.g. <c>api/invoices/{id}</c>. Null for non-routable endpoints.</summary>
    public string? RoutePattern { get; init; }

    /// <summary>HTTP methods the endpoint answers. Empty means "all methods".</summary>
    public IReadOnlyList<string> HttpMethods { get; init; } = [];

    /// <summary>True when any <c>IAuthorizeData</c> metadata is present.</summary>
    public bool RequiresAuthorization { get; init; }

    /// <summary>True when <c>[AllowAnonymous]</c> is present, which overrides any authorization metadata.</summary>
    public bool AllowsAnonymous { get; init; }

    /// <summary>Named policies referenced by the endpoint's authorization metadata.</summary>
    public IReadOnlyList<string> Policies { get; init; } = [];

    /// <summary>Roles referenced by the endpoint's authorization metadata.</summary>
    public IReadOnlyList<string> Roles { get; init; } = [];

    /// <summary>Route parameter names, e.g. <c>id</c> for <c>api/invoices/{id}</c>.</summary>
    public IReadOnlyList<string> RouteParameters { get; init; } = [];

    /// <summary>
    /// True when a route parameter looks like it addresses a specific stored object.
    /// These are the endpoints where broken object level authorization (IDOR) lives.
    /// </summary>
    public bool ExposesResourceIdentifier { get; init; }

    /// <summary>
    /// Requirement type names from any <c>AuthorizationPolicy</c> attached directly to the
    /// endpoint — which is how inline policies built by
    /// <c>RequireAuthorization(configure)</c> are represented.
    /// </summary>
    public IReadOnlyList<string> PolicyRequirements { get; init; } = [];

    /// <summary>
    /// What the handler's own code says about whether it can scope to the caller.
    /// See <see cref="Scanning.HandlerPrincipalInspector"/>.
    /// </summary>
    public HandlerInspection Handler { get; init; } = HandlerInspection.Unknown;

    /// <summary>
    /// True when authorization asks for something beyond "the caller is signed in".
    /// A bare <c>DenyAnonymousAuthorizationRequirement</c> does not count.
    /// </summary>
    public bool HasSubstantiveRequirement =>
        PolicyRequirements.Any(r =>
            !string.Equals(r, "DenyAnonymousAuthorizationRequirement", StringComparison.Ordinal));

    /// <summary>
    /// Effective reachability: an endpoint is anonymously reachable when it either
    /// opts out explicitly, or simply never opted in.
    /// </summary>
    public bool IsAnonymouslyReachable => AllowsAnonymous || !RequiresAuthorization;

    /// <summary>Method-and-route form, e.g. <c>GET /api/invoices/{id}</c>.</summary>
    public override string ToString()
    {
        var route = "/" + (RoutePattern ?? string.Empty).TrimStart('/');

        return HttpMethods.Count > 0
            ? $"{string.Join(",", HttpMethods)} {route}"
            : route;
    }
}
