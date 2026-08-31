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
        var analysed = new List<HttpEndpointInfo>();

        foreach (var endpoint in endpoints)
        {
            if (options.IsIgnored(endpoint.RoutePattern))
            {
                continue;
            }

            if (endpoint.IsInfrastructureEndpoint && !options.IncludeInfrastructureEndpoints)
            {
                continue;
            }

            analysed.Add(endpoint);

            foreach (var finding in Evaluate(endpoint, options))
            {
                if (!options.SuppressedCodes.Contains(finding.Code))
                {
                    findings.Add(finding);
                }
            }
        }

        var baseline = options.Baseline;

        if (baseline is null)
        {
            return new AuthorizationSurfaceReport(analysed, findings, options.FailOn);
        }

        var baselined = findings.Where(baseline.Covers).ToArray();
        var newFindings = findings.Where(f => !baseline.Covers(f)).ToArray();

        return new AuthorizationSurfaceReport(
            analysed,
            newFindings,
            options.FailOn,
            baselined,
            baseline.StaleEntries(findings));
    }

    private static IEnumerable<Finding> Evaluate(HttpEndpointInfo endpoint, AuthzProbeOptions options)
    {
        var name = endpoint.ToString();

        // AZP001 — nothing opted this endpoint in. The most common cause of a wide-open API
        // is not a wrong policy, it's a missing attribute on a new controller. An endpoint
        // covered by the application's fallback policy is not in this category: the scanner
        // reports it as requiring authorization, because that is what the middleware enforces.
        if (!endpoint.RequiresAuthorization && !endpoint.AllowsAnonymous)
        {
            yield return new Finding
            {
                Code = FindingCodes.ImplicitlyAnonymous,
                Severity = FindingSeverity.Error,
                Title = "Endpoint is reachable without authentication",
                Detail =
                    "The endpoint carries no authorization metadata and no explicit [AllowAnonymous], "
                    + "and the application configures no fallback policy to catch it. It is anonymous "
                    + "by omission rather than by decision, so nothing distinguishes it from an endpoint "
                    + "someone forgot to protect.",
                Endpoint = name,
                Remediation =
                    "Add [Authorize] (or RequireAuthorization()), or add [AllowAnonymous] to record that "
                    + "public access is intended. Consider a fallback policy so the default is deny."
            };

            yield break;
        }

        var addressedByRouteOrQuery = endpoint.ExposesResourceIdentifier;
        var addressedByBody = endpoint.BodyIdentifiers.Count > 0;

        if (!addressedByRouteOrQuery && !addressedByBody)
        {
            yield break;
        }

        // AZP003 — explicitly public *and* addressing a specific object.
        if (endpoint.AllowsAnonymous && addressedByRouteOrQuery)
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

        // A named policy we could not resolve could be doing anything at all. Reporting
        // on it would be a guess in either direction, so report nothing.
        if (!endpoint.AuthorizationResolved)
        {
            yield break;
        }

        // An identifier that only ever appears in the request body cannot be judged by the
        // route rules, which have nothing to look at. It gets its own review-level finding
        // rather than being folded into a high-confidence one.
        if (!addressedByRouteOrQuery)
        {
            var scopedDeclaratively = endpoint.HasSubstantiveRequirement && !endpoint.RolesAreTheOnlyCheck;

            if (!scopedDeclaratively && endpoint.Handler is not HandlerInspection.PrincipalAware)
            {
                yield return new Finding
                {
                    Code = FindingCodes.BodyResourceAccess,
                    Severity = FindingSeverity.Info,
                    Title = "Endpoint takes an object identifier in its request body",
                    Detail =
                        "The route template shows no identifier, but the handler binds one from the "
                        + "request body. Authorization stops at 'signed in' or at a role, and the "
                        + "handler does not reference the caller, so the caller chooses which object "
                        + "is acted on. This is the same defect as an unscoped route identifier, "
                        + "hidden from the route table. Body binding is inferred from the handler's "
                        + "signature, so review rather than assume.",
                    Endpoint = name,
                    Evidence = "binds " + string.Join(", ", endpoint.BodyIdentifiers),
                    Remediation =
                        "Derive the object's owner from the authenticated principal and reject a body "
                        + "whose identifier does not belong to them, or apply a resource-based policy."
                };
            }

            yield break;
        }

        // AZP004 — a role says what kind of user you are, never which rows are yours.
        // Only raise it when roles are the *whole* check: a policy carrying some other
        // requirement alongside the role may well be doing the ownership test.
        if (endpoint.RolesAreTheOnlyCheck)
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

            yield break;
        }

        // Authorization asks for something beyond "signed in", so it may well be the
        // ownership check. Nothing to report.
        if (endpoint.HasSubstantiveRequirement)
        {
            yield break;
        }

        // Whether "signed in and nothing more" is a defect depends on what the handler
        // itself can see, so split on that rather than reporting everything at once.

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
                "The endpoint takes an identifier that addresses a stored object, the authorization "
                + "it enforces stops at 'is this caller signed in', and the handler's own code never "
                + "references the authenticated principal. It therefore has no way to know who is "
                + "calling and cannot be filtering by them, so any authenticated user can substitute "
                + "another user's identifier. This is broken object level authorization (OWASP API1). "
                + "Note that a policy is judged by the requirements it actually carries, so a named "
                + "policy that only calls RequireAuthenticatedUser is reported here.",
            Endpoint = name,
            Remediation =
                "Enforce ownership server-side: derive the owner from the authenticated principal "
                + "rather than the request, or apply a resource-based policy via IAuthorizationService.",
        };
    }
}
