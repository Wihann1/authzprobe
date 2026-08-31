using System.Reflection;
using AuthzProbe.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthzProbe.Scanning;

/// <summary>
/// Reads the application's routing table and reports what authorization each endpoint
/// actually enforces at runtime — including conventions applied globally, named policies
/// resolved to their requirements, and the fallback policy, none of which source
/// inspection or a literal read of endpoint metadata would see.
/// </summary>
public static class EndpointSurfaceScanner
{
    /// <summary>
    /// Scans every endpoint registered on the route builder — typically your
    /// <c>WebApplication</c>, before it runs.
    /// </summary>
    /// <remarks>
    /// Prefer this overload at startup. Minimal-API endpoints are held on the builder's
    /// own data sources and are only merged into the container's composite
    /// <see cref="EndpointDataSource"/> once the routing middleware is built, so resolving
    /// from the service provider before <c>Run</c> reports nothing. It also carries the
    /// builder's services, which is what lets named and fallback policies be resolved.
    /// </remarks>
    public static IReadOnlyList<HttpEndpointInfo> Scan(IEndpointRouteBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var lookup = PolicyLookup.From(builder.ServiceProvider);

        return builder.DataSources.SelectMany(source => Scan(source, lookup)).ToArray();
    }

    /// <summary>
    /// Scans every endpoint registered in the application's service provider.
    /// </summary>
    /// <remarks>
    /// Use this once the application is running — for example inside a
    /// <c>WebApplicationFactory</c> integration test. Before the pipeline is built,
    /// prefer the <see cref="Scan(IEndpointRouteBuilder)"/> overload.
    /// </remarks>
    public static IReadOnlyList<HttpEndpointInfo> Scan(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);

        var source = services.GetRequiredService<EndpointDataSource>();
        return Scan(source, PolicyLookup.From(services));
    }

    /// <summary>Scans every endpoint exposed by the given data source.</summary>
    /// <remarks>
    /// Without services, named policies cannot be resolved and the fallback policy is
    /// invisible. Endpoints guarded by a named policy are reported as unresolved and raise
    /// nothing. Prefer <see cref="Scan(EndpointDataSource, IServiceProvider)"/>.
    /// </remarks>
    public static IReadOnlyList<HttpEndpointInfo> Scan(EndpointDataSource source)
    {
        ArgumentNullException.ThrowIfNull(source);

        return Scan(source, PolicyLookup.None);
    }

    /// <summary>
    /// Scans a data source, resolving named and fallback policies against the given services.
    /// </summary>
    public static IReadOnlyList<HttpEndpointInfo> Scan(EndpointDataSource source, IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(services);

        return Scan(source, PolicyLookup.From(services));
    }

    private static IReadOnlyList<HttpEndpointInfo> Scan(EndpointDataSource source, PolicyLookup lookup)
    {
        var results = new List<HttpEndpointInfo>();

        foreach (var endpoint in source.Endpoints)
        {
            if (endpoint is not RouteEndpoint route)
            {
                continue;
            }

            results.Add(Describe(route, lookup));
        }

        return results;
    }

    /// <summary>
    /// Endpoints that serve files or routing infrastructure rather than application data.
    /// </summary>
    /// <remarks>
    /// <c>MapStaticAssets</c> registers one endpoint per file — several hundred in a stock
    /// MVC or Blazor application, each of them anonymous. Reporting them buries the handful
    /// of findings that matter under a wall of CSS.
    /// </remarks>
    private static readonly string[] InfrastructureMetadataTypes =
    [
        "Microsoft.AspNetCore.StaticAssets.StaticAssetDescriptor",
        "Microsoft.AspNetCore.Routing.FallbackMetadata"
    ];

    private static bool IsInfrastructure(EndpointMetadataCollection metadata) =>
        metadata.Any(m => InfrastructureMetadataTypes.Contains(m.GetType().FullName, StringComparer.Ordinal));

    /// <summary>
    /// Finds the methods that actually run for an endpoint.
    /// </summary>
    /// <remarks>
    /// Each of the three routing styles hides the handler somewhere different. Minimal APIs
    /// put the delegate's <see cref="MethodInfo"/> straight into endpoint metadata.
    /// Controllers carry a <c>ControllerActionDescriptor</c> instead. Razor Pages carry a
    /// <c>CompiledPageActionDescriptor</c> holding one method per handler — <c>OnGet</c>,
    /// <c>OnPost</c> and friends. Reading only the first leaves controllers and pages
    /// uninspectable, which quietly downgrades most of a real application to a review list.
    /// </remarks>
    private static IReadOnlyCollection<MethodInfo> FindHandlerMethods(EndpointMetadataCollection metadata)
    {
        if (metadata.GetMetadata<MethodInfo>() is { } method)
        {
            return [method];
        }

        if (metadata.GetMetadata<ControllerActionDescriptor>()?.MethodInfo is { } action)
        {
            return [action];
        }

        if (metadata.GetMetadata<CompiledPageActionDescriptor>()?.HandlerMethods is { } handlers)
        {
            return handlers
                .Select(h => h.MethodInfo)
                .Where(m => m is not null)
                .ToArray();
        }

        return [];
    }

    /// <summary>Names the action behind a controller endpoint, e.g. <c>Home.Index</c>.</summary>
    private static string? FindHandlerName(EndpointMetadataCollection metadata) =>
        metadata.GetMetadata<ControllerActionDescriptor>() is { } action
            ? $"{action.ControllerName}.{action.ActionName}"
            : null;

    private static HttpEndpointInfo Describe(RouteEndpoint route, PolicyLookup lookup)
    {
        var metadata = route.Metadata;
        var authorizeData = metadata.GetOrderedMetadata<IAuthorizeData>();
        var attachedPolicies = metadata.GetOrderedMetadata<AuthorizationPolicy>();
        var allowAnonymous = metadata.GetMetadata<IAllowAnonymous>() is not null;
        var methods = metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? [];

        var pattern = route.RoutePattern.RawText;
        var parameters = ResourceIdentifierHeuristics.ExtractRouteParameters(pattern);

        var declaresAuthorization = authorizeData.Count > 0 || attachedPolicies.Count > 0;

        // An endpoint that declares nothing is not necessarily unprotected: unless it opts
        // out with [AllowAnonymous], the fallback policy is what the middleware evaluates.
        var coveredByFallback = !declaresAuthorization
                                && !allowAnonymous
                                && lookup.FallbackPolicy is not null;

        AuthorizationPolicy? effective;
        bool resolved;

        if (declaresAuthorization)
        {
            (effective, resolved) = lookup.Combine(authorizeData, attachedPolicies);
        }
        else
        {
            effective = coveredByFallback ? lookup.FallbackPolicy : null;
            resolved = true;
        }

        // A bare [Authorize] resolves to the application's default policy. If that policy carries
        // a real requirement, this endpoint counts as declaratively scoped without anything on it
        // having said so — and so does every other authorized endpoint in the application.
        var declaredOnlyBareAuthorize =
            authorizeData.Count > 0
            && attachedPolicies.Count == 0
            && authorizeData.All(a => string.IsNullOrWhiteSpace(a.Policy) && string.IsNullOrWhiteSpace(a.Roles));

        var defaultPolicyIsSubstantive = lookup.DefaultPolicy?.Requirements
            .Any(r => !string.Equals(r.GetType().Name, "DenyAnonymousAuthorizationRequirement", StringComparison.Ordinal)) == true;

        var requirementNames = effective?.Requirements
            .Select(r => r.GetType().Name)
            .Distinct(StringComparer.Ordinal)
            .ToArray() ?? [];

        var policies = authorizeData
            .Select(a => a.Policy)
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => p!)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var attributeRoles = authorizeData
            .Select(a => a.Roles)
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .SelectMany(r => r!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

        var policyRoles = effective?.Requirements
            .OfType<RolesAuthorizationRequirement>()
            .SelectMany(r => r.AllowedRoles) ?? [];

        var roles = attributeRoles
            .Concat(policyRoles)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var handlers = FindHandlerMethods(metadata);
        var identifiers = HandlerParameterInspector.Inspect(handlers, parameters);

        return new HttpEndpointInfo
        {
            DisplayName = route.DisplayName ?? pattern ?? "(unnamed endpoint)",
            IsInfrastructureEndpoint = IsInfrastructure(metadata),
            HandlerName = FindHandlerName(metadata),
            RoutePattern = pattern,
            HttpMethods = [.. methods],
            RequiresAuthorization = declaresAuthorization || coveredByFallback,
            CoveredByFallbackPolicy = coveredByFallback,
            AuthorizationResolved = resolved,
            ScopingCameFromDefaultPolicy = declaredOnlyBareAuthorize && defaultPolicyIsSubstantive,
            PolicyRequirements = requirementNames,
            AllowsAnonymous = allowAnonymous,
            Policies = policies,
            Roles = roles,
            RouteParameters = parameters,
            ExposesResourceIdentifier =
                parameters.Any(ResourceIdentifierHeuristics.LooksLikeResourceIdentifier)
                || identifiers.Query.Count > 0,
            QueryIdentifiers = identifiers.Query,
            BodyIdentifiers = identifiers.Body,
            Handler = HandlerPrincipalInspector.InspectAll(handlers)
        };
    }
}
