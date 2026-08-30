using AuthzProbe.Model;
using AuthzProbe.Scanning;
using Microsoft.AspNetCore.Routing;

namespace AuthzProbe.Analysis;

/// <summary>
/// Applies the rule set to a scanned endpoint surface.
/// </summary>
/// <remarks>
/// The rules deliberately target the class of defect that static analysis cannot reach.
/// A SAST tool can prove a query is parameterised; it cannot know that
/// <c>GET /invoices/{id}</c> should only return invoices belonging to the caller,
/// because ownership is a property of your domain, not of the syntax.
/// What this analyzer can do is find every endpoint where that question is
/// unanswered — which is where the answer is usually "it doesn't check".
/// </remarks>
public static class AuthorizationSurfaceAnalyzer
{
    /// <summary>
    /// Scans and analyses the endpoints registered on the route builder — typically your
    /// <c>WebApplication</c>, before it runs. This is the overload to use at startup.
    /// </summary>
    public static AuthorizationSurfaceReport Analyze(
        IEndpointRouteBuilder builder,
        AuthzProbeOptions? options = null)
    {
        var endpoints = EndpointSurfaceScanner.Scan(builder);
        return Analyze(endpoints, options);
    }

    /// <summary>Scans and analyses the endpoints registered in the given service provider.</summary>
    public static AuthorizationSurfaceReport Analyze(
        IServiceProvider services,
        AuthzProbeOptions? options = null)
    {
        var endpoints = EndpointSurfaceScanner.Scan(services);
        return Analyze(endpoints, options);
    }

    /// <summary>Scans and analyses the endpoints exposed by the given data source.</summary>
    public static AuthorizationSurfaceReport Analyze(
        EndpointDataSource source,
        AuthzProbeOptions? options = null)
    {
        var endpoints = EndpointSurfaceScanner.Scan(source);
        return Analyze(endpoints, options);
    }

    /// <summary>Analyses an already-scanned surface.</summary>
    public static AuthorizationSurfaceReport Analyze(
        IReadOnlyList<HttpEndpointInfo> endpoints,
        AuthzProbeOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        options ??= new AuthzProbeOptions();

        var findings = new List<Finding>();

        foreach (var endpoint in endpoints)
        {
            if (options.IsIgnored(endpoint.RoutePattern))
            {
                continue;
            }

            foreach (var finding in Evaluate(endpoint, options))
            {
                if (!options.SuppressedCodes.Contains(finding.Code))
                {
                    findings.Add(finding);
                }
            }
        }

        return new AuthorizationSurfaceReport(endpoints, findings, options.FailOn);
    }

    private static IEnumerable<Finding> Evaluate(HttpEndpointInfo endpoint, AuthzProbeOptions options)
    {
        var name = endpoint.ToString();

        // AZP001 — nothing opted this endpoint in. The most common cause of a wide-open API
        // is not a wrong policy, it's a missing attribute on a new controller.
        if (!endpoint.RequiresAuthorization && !endpoint.AllowsAnonymous)
        {
            yield return new Finding
            {
                Code = FindingCodes.ImplicitlyAnonymous,
                Severity = FindingSeverity.Error,
                Title = "Endpoint is reachable without authentication",
                Detail =
                    "The endpoint carries no authorization metadata and no explicit [AllowAnonymous]. "
                    + "It is anonymous by omission rather than by decision, so nothing distinguishes it "
                    + "from an endpoint someone forgot to protect.",
                Endpoint = name,
                Remediation =
                    "Add [Authorize] (or RequireAuthorization()), or add [AllowAnonymous] to record that "
                    + "public access is intended. Consider a fallback policy so the default is deny."
            };

            yield break;
        }

        if (!endpoint.ExposesResourceIdentifier)
        {
            yield break;
        }

        // AZP003 — explicitly public *and* addressing a specific object.
        if (endpoint.AllowsAnonymous)
        {
            yield return new Finding
            {
                Code = FindingCodes.AnonymousResourceAccess,
                Severity = FindingSeverity.Warning,
                Title = "Anonymous endpoint addresses a specific object",
                Detail =
                    "The endpoint is explicitly anonymous but takes an identifier that appears to address "
                    + "a stored object. Anyone who can guess or enumerate the identifier can read it.",
                Endpoint = name,
                Remediation =
                    "Confirm the object is genuinely public. If it is not, remove [AllowAnonymous] and "
                    + "add a resource-based check. If it is, prefer an unguessable identifier."
            };

            yield break;
        }

        // No declarative scoping. Whether that is a defect depends on what the handler
        // itself can see, so split on that rather than reporting everything at once.
        if (endpoint.Policies.Count == 0
            && endpoint.Roles.Count == 0
            && !endpoint.HasSubstantiveRequirement)
        {
            // AZP005 — either the handler touches the principal and may be checking
            // ownership in its body, or we could not read it at all. Neither supports
            // the claim AZP002 makes, so both go to the review list.
            if (endpoint.Handler is HandlerInspection.PrincipalAware or HandlerInspection.Unknown)
            {
                yield return new Finding
                {
                    Code = FindingCodes.UnverifiedResourceAccess,
                    Severity = FindingSeverity.Info,
                    Title = "Object-addressing endpoint scopes access in the handler, not declaratively",
                    Detail =
                        "The endpoint takes an object identifier and carries no resource-based policy, "
                        + "but its handler either references the authenticated principal — so it may well "
                        + "be enforcing ownership in its body — or could not be inspected. AuthzProbe "
                        + "cannot tell whether a check exists or whether it is the right one. "
                        + "This is a review list, not a defect list.",
                    Endpoint = name,
                    Remediation =
                        "Confirm the handler filters by the caller rather than merely reading their "
                        + "identity. Moving the check into a resource-based policy makes it verifiable."
                };

                yield break;
            }

            // AZP002 — the handler never references the caller, so it cannot be filtering
            // by them. This is the high-confidence case.
            yield return new Finding
            {
                Code = FindingCodes.UnscopedResourceAccess,
                Severity = options.TreatUnscopedResourceAccessAsError
                    ? FindingSeverity.Error
                    : FindingSeverity.Warning,
                Title = "Object-addressing endpoint cannot be scoping to the caller",
                Detail =
                    "The endpoint takes an identifier that addresses a stored object, authorization stops "
                    + "at 'is this caller signed in', and the handler's own code never references the "
                    + "authenticated principal. It therefore has no way to know who is calling and cannot "
                    + "be filtering by them, so any authenticated user can substitute another user's "
                    + "identifier. This is broken object level authorization (OWASP API1).",
                Endpoint = name,
                Remediation =
                    "Enforce ownership server-side: derive the owner from the authenticated principal "
                    + "rather than the request, or apply a resource-based policy via IAuthorizationService.",
            };

            yield break;
        }

        // AZP004 — a role says what kind of user you are, never which rows are yours.
        // Only raise it when roles are the *whole* check: a policy carrying some other
        // requirement alongside the role may well be doing the ownership test.
        var rolesAreTheOnlyCheck = endpoint.PolicyRequirements.All(r =>
            r is "DenyAnonymousAuthorizationRequirement" or "RolesAuthorizationRequirement");

        if (endpoint.Policies.Count == 0 && endpoint.Roles.Count > 0 && rolesAreTheOnlyCheck)
        {
            yield return new Finding
            {
                Code = FindingCodes.RoleOnlyResourceAccess,
                Severity = FindingSeverity.Info,
                Title = "Object-addressing endpoint is guarded only by a role check",
                Detail =
                    "The endpoint addresses a stored object and is guarded by a role. A role establishes "
                    + "what kind of user the caller is, not which objects belong to them, so every holder "
                    + "of the role can reach every object.",
                Endpoint = name,
                Remediation =
                    "Add a resource-based authorization check in addition to the role, unless the role is "
                    + "genuinely intended to grant access to every instance."
            };
        }
    }
}
