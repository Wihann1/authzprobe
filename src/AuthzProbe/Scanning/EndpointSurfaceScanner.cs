using System.Reflection;
using AuthzProbe.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthzProbe.Scanning;

/// <summary>
/// Reads the application's routing table and reports what authorization metadata
/// each endpoint actually carries at runtime — including conventions applied globally,
/// which source inspection alone would miss.
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
    /// from the service provider before <c>Run</c> reports nothing.
    /// </remarks>
    public static IReadOnlyList<HttpEndpointInfo> Scan(IEndpointRouteBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.DataSources.SelectMany(Scan).ToArray();
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
        return Scan(source);
    }

    /// <summary>Scans every endpoint exposed by the given data source.</summary>
    public static IReadOnlyList<HttpEndpointInfo> Scan(EndpointDataSource source)
    {
        ArgumentNullException.ThrowIfNull(source);

        var results = new List<HttpEndpointInfo>();

        foreach (var endpoint in source.Endpoints)
        {
            if (endpoint is not RouteEndpoint route)
            {
                continue;
            }

            var metadata = route.Metadata;
            var authorizeData = metadata.GetOrderedMetadata<IAuthorizeData>();
            var allowAnonymous = metadata.GetMetadata<IAllowAnonymous>() is not null;
            var methods = metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? [];

            var pattern = route.RoutePattern.RawText;
            var parameters = ResourceIdentifierHeuristics.ExtractRouteParameters(pattern);

            var policies = authorizeData
                .Select(a => a.Policy)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Select(p => p!)
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            // RequireAuthorization(configure) compiles its rules into an AuthorizationPolicy
            // attached to the endpoint, so roles configured that way never appear on
            // IAuthorizeData. Read both, or inline policies are invisible.
            var policy = metadata.GetMetadata<AuthorizationPolicy>();

            var requirementNames = policy?.Requirements
                .Select(r => r.GetType().Name)
                .Distinct(StringComparer.Ordinal)
                .ToArray() ?? [];

            var attributeRoles = authorizeData
                .Select(a => a.Roles)
                .Where(r => !string.IsNullOrWhiteSpace(r))
                .SelectMany(r => r!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

            var policyRoles = policy?.Requirements
                .OfType<RolesAuthorizationRequirement>()
                .SelectMany(r => r.AllowedRoles) ?? [];

            var roles = attributeRoles
                .Concat(policyRoles)
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            results.Add(new HttpEndpointInfo
            {
                DisplayName = endpoint.DisplayName ?? pattern ?? "(unnamed endpoint)",
                RoutePattern = pattern,
                HttpMethods = [.. methods],
                RequiresAuthorization = authorizeData.Count > 0 || policy is not null,
                PolicyRequirements = requirementNames,
                AllowsAnonymous = allowAnonymous,
                Policies = policies,
                Roles = roles,
                RouteParameters = parameters,
                ExposesResourceIdentifier =
                    parameters.Any(ResourceIdentifierHeuristics.LooksLikeResourceIdentifier),
                Handler = HandlerPrincipalInspector.Inspect(metadata.GetMetadata<MethodInfo>())
            });
        }

        return results;
    }
}
