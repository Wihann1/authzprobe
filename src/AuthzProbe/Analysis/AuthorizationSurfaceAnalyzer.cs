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

        findings = CollapseWhenNothingIsObservable(findings, analysed, options);

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

    /// <summary>
    /// Replaces a wall of AZP001s with one finding when the entire surface lacks authorization
    /// metadata.
    /// </summary>
    /// <remarks>
    /// Some applications enforce access with their own MVC filters, middleware or an upstream
    /// gateway rather than with ASP.NET Core authorization. nopCommerce is one: it has no
    /// AddAuthorization call anywhere and guards its admin area with permission filters, so a
    /// literal reading of its routing table produced 1,675 findings on 1,675 endpoints. Every
    /// one was true and the report was worthless — the same failure as reporting a stylesheet
    /// per file. Saying it once, and saying what it means, is the useful answer.
    /// </remarks>
    private static List<Finding> CollapseWhenNothingIsObservable(
        List<Finding> findings,
        IReadOnlyList<HttpEndpointInfo> analysed,
        AuthzProbeOptions options)
    {
        var anonymous = findings.Where(f => f.Code == FindingCodes.ImplicitlyAnonymous).ToList();

        // Only when the surface is large enough for the absence to mean something, and
        // practically nothing on it is protected.
        if (analysed.Count < MinimumSurfaceForCollapse
            || anonymous.Count < MinimumSurfaceForCollapse
            || anonymous.Count < analysed.Count * UnprotectedShareForCollapse
            || options.SuppressedCodes.Contains(FindingCodes.AuthorizationNotObservable))
        {
            return findings;
        }

        var collapsed = findings.Where(f => f.Code != FindingCodes.ImplicitlyAnonymous).ToList();

        collapsed.Insert(0, new Finding
        {
            Code = FindingCodes.AuthorizationNotObservable,
            Severity = FindingSeverity.Error,
            Title = "No endpoint on this surface carries authorization metadata",
            Detail =
                $"{anonymous.Count} of {analysed.Count} analysed endpoints have no authorization "
                + "metadata and no [AllowAnonymous]. When it is the whole surface rather than a few "
                + "endpoints, the likeliest explanation is not that everything is unprotected but "
                + "that this application enforces access some other way — its own MVC filters, "
                + "middleware, or an upstream gateway — which AuthzProbe cannot see. Treat this "
                + "report as inconclusive rather than as a clean bill of health, because the object "
                + "level rules depend on reading authorization that is not there to read. If the "
                + "application is meant to use ASP.NET Core authorization, then the surface really "
                + "is open and this is the finding to act on.",
            Evidence = $"{anonymous.Count} of {analysed.Count} endpoints",
            Remediation =
                "If access is enforced by custom filters or middleware, AuthzProbe is the wrong "
                + "tool for this application until that moves to ASP.NET Core authorization. "
                + "Otherwise add a fallback policy so the default is deny, and [AllowAnonymous] "
                + "where public access is intended."
        });

        return collapsed;
    }

    /// <summary>Below this many endpoints, an absence of metadata is not evidence of a pattern.</summary>
    private const int MinimumSurfaceForCollapse = 20;

    /// <summary>How much of the surface must be unprotected before it reads as "all of it".</summary>
    private const double UnprotectedShareForCollapse = 0.98;

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

        // AZP002 — nothing observable scopes this endpoint to the caller. This is the
        // highest-confidence case the tool has, which is not the same as certainty: the
        // wording states what was observed and leaves the conclusion to the reader.
        yield return new Finding
        {
            Code = FindingCodes.UnscopedResourceAccess,
            Severity = options.TreatUnscopedResourceAccessAsError
                ? FindingSeverity.Error
                : FindingSeverity.Warning,
            Title = "Object-addressing endpoint shows no sign of scoping to the caller",
            Detail =
                "Three things were observed. The endpoint takes an identifier that addresses a "
                + "stored object. The authorization it enforces stops at 'is this caller signed in' "
                + "— a policy is judged by the requirements it carries, so one that only calls "
                + "RequireAuthenticatedUser counts as nothing more. And neither the handler's own "
                + "code nor the methods it calls directly reference the authenticated principal. "
                + "Together those are the shape of broken object level authorization (OWASP API1), "
                + "where one authenticated user substitutes another's identifier. "
                + "This is a finding to check, not a proven vulnerability: ownership enforced "
                + "through an injected service, further down the call graph, or by middleware or a "
                + "gateway outside this application is invisible here and would make this a false "
                + "positive. See the limitations in the README.",
            Endpoint = name,
            Remediation =
                "Enforce ownership server-side: derive the owner from the authenticated principal "
                + "rather than the request, or apply a resource-based policy via IAuthorizationService.",
        };
    }
}
