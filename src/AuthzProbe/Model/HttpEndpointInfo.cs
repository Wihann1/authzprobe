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
    /// The action behind the endpoint, e.g. <c>Home.Index</c>, when routing alone does not
    /// identify it. Conventionally routed MVC actions all share one route template, so the
    /// template on its own names four different endpoints identically.
    /// </summary>
    public string? HandlerName { get; init; }

    /// <summary>
    /// True when the endpoint serves files or routing infrastructure rather than application
    /// data — a static asset registered by <c>MapStaticAssets</c>, or a routing fallback.
    /// A stock MVC application registers several hundred of these, and none of them can
    /// address a caller-owned object.
    /// </summary>
    public bool IsInfrastructureEndpoint { get; init; }

    /// <summary>
    /// True when the endpoint carries no authorization metadata of its own and is protected
    /// by the application's fallback policy. Such an endpoint is not anonymous, even though
    /// nothing is declared on it.
    /// </summary>
    public bool CoveredByFallbackPolicy { get; init; }

    /// <summary>
    /// True when the requirements actually enforced at runtime are known. False when a named
    /// policy could not be resolved, in which case no conclusion may be drawn about scoping —
    /// the policy could be doing anything.
    /// </summary>
    public bool AuthorizationResolved { get; init; } = true;

    /// <summary>
    /// True when authorization asks for something beyond "the caller is signed in".
    /// A bare <c>DenyAnonymousAuthorizationRequirement</c> does not count.
    /// </summary>
    public bool HasSubstantiveRequirement =>
        PolicyRequirements.Any(r =>
            !string.Equals(r, "DenyAnonymousAuthorizationRequirement", StringComparison.Ordinal));

    /// <summary>
    /// True when roles are the whole of the check. A policy carrying some other requirement
    /// alongside the role may well be doing the ownership test.
    /// </summary>
    public bool RolesAreTheOnlyCheck =>
        Roles.Count > 0
        && PolicyRequirements.All(r =>
            r is "DenyAnonymousAuthorizationRequirement" or "RolesAuthorizationRequirement");

    /// <summary>
    /// Method-and-route form, e.g. <c>GET /api/invoices/{id}</c>, with the action name
    /// appended when the route template does not identify the endpoint on its own.
    /// </summary>
    public override string ToString()
    {
        var route = "/" + (RoutePattern ?? string.Empty).TrimStart('/');

        var identity = HttpMethods.Count > 0
            ? $"{string.Join(",", HttpMethods)} {route}"
            : route;

        return HandlerName is not null && RouteTemplateIsShared
            ? $"{identity} \u2192 {HandlerName}"
            : identity;
    }

    /// <summary>
    /// True for a conventional MVC route, where one template serves every action and so
    /// cannot identify a single endpoint.
    /// </summary>
    private bool RouteTemplateIsShared =>
        RoutePattern is not null
        && (RoutePattern.Contains("{controller", StringComparison.OrdinalIgnoreCase)
            || RoutePattern.Contains("{action", StringComparison.OrdinalIgnoreCase));
}
