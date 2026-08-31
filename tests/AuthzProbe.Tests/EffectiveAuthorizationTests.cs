using System.Security.Claims;
using AuthzProbe.Analysis;
using AuthzProbe.Model;
using AuthzProbe.Scanning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SampleApi;

namespace AuthzProbe.Tests;

/// <summary>
/// Covers the gap between what an endpoint <em>declares</em> and what the authorization
/// middleware actually <em>enforces</em>: fallback policies, named policies, and endpoints
/// that reach the routing table through MVC rather than as minimal APIs.
/// </summary>
public class EffectiveAuthorizationTests
{
    private sealed class OwnershipRequirement : IAuthorizationRequirement;

    private static WebApplication BuildApp(
        Action<AuthorizationOptions>? authorization = null,
        Action<IEndpointRouteBuilder>? map = null,
        Action<IServiceCollection>? services = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthentication();
        builder.Services.AddAuthorization(options => authorization?.Invoke(options));
        services?.Invoke(builder.Services);

        var app = builder.Build();
        map?.Invoke(app);
        return app;
    }

    // --- fallback policy ---------------------------------------------------------------

    [Fact]
    public void An_endpoint_covered_by_the_fallback_policy_is_not_reported_as_anonymous()
    {
        // Deny-by-default is the configuration AZP001's own remediation recommends.
        // Reporting it as "anonymous by omission" would fail the build of every
        // application that took the advice.
        var app = BuildApp(
            authorization: o => o.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build(),
            map: a => a.MapGet("/api/reports", () => Results.Ok()));

        var report = AuthorizationSurfaceAnalyzer.Analyze(app);

        Assert.DoesNotContain(FindingCodes.ImplicitlyAnonymous, report.Findings.Select(f => f.Code));
        Assert.True(report.Passed);
    }

    [Fact]
    public void The_same_endpoint_is_reported_as_anonymous_without_a_fallback_policy()
    {
        var app = BuildApp(map: a => a.MapGet("/api/reports", () => Results.Ok()));

        var report = AuthorizationSurfaceAnalyzer.Analyze(app);

        var finding = Assert.Single(report.Findings);
        Assert.Equal(FindingCodes.ImplicitlyAnonymous, finding.Code);
    }

    [Fact]
    public void A_fallback_policy_is_recorded_on_the_scanned_endpoint()
    {
        var app = BuildApp(
            authorization: o => o.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build(),
            map: a => a.MapGet("/api/reports", () => Results.Ok()));

        var endpoint = Assert.Single(EndpointSurfaceScanner.Scan(app));

        Assert.True(endpoint.CoveredByFallbackPolicy);
        Assert.True(endpoint.RequiresAuthorization);
    }

    [Fact]
    public void A_fallback_policy_does_not_rescue_an_object_addressing_endpoint()
    {
        // Deny-by-default answers "is the caller signed in", never "is this row theirs".
        var app = BuildApp(
            authorization: o => o.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build(),
            map: a => a.MapGet("/api/invoices/{id}", (string id) => Results.Ok(new { id })));

        var report = AuthorizationSurfaceAnalyzer.Analyze(app);

        var finding = Assert.Single(report.Findings);
        Assert.Equal(FindingCodes.UnscopedResourceAccess, finding.Code);
    }

    [Fact]
    public void An_explicitly_anonymous_endpoint_is_not_treated_as_covered_by_the_fallback()
    {
        // AllowAnonymous opts out of the fallback at runtime, so the scan must not
        // credit it with protection the middleware will never apply.
        var app = BuildApp(
            authorization: o => o.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build(),
            map: a => a.MapGet("/api/payslips/{payslipId}", (string payslipId) => Results.Ok())
                       .AllowAnonymous());

        var endpoint = Assert.Single(EndpointSurfaceScanner.Scan(app));
        Assert.False(endpoint.CoveredByFallbackPolicy);

        var finding = Assert.Single(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);
        Assert.Equal(FindingCodes.AnonymousResourceAccess, finding.Code);
    }

    // --- named policies ----------------------------------------------------------------

    [Fact]
    public void A_named_policy_that_only_requires_authentication_does_not_count_as_scoping()
    {
        // The policy is named like an ownership rule and enforces nothing of the kind.
        // Accepting the name at face value is how a scanner misses the defect it exists
        // to find.
        var app = BuildApp(
            authorization: o => o.AddPolicy("MustOwnTheRecord", p => p.RequireAuthenticatedUser()),
            map: a => a.MapGet("/api/invoices/{id}", (string id) => Results.Ok(new { id }))
                       .RequireAuthorization("MustOwnTheRecord"));

        var finding = Assert.Single(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);

        Assert.Equal(FindingCodes.UnscopedResourceAccess, finding.Code);
    }

    [Fact]
    public void A_named_policy_carrying_a_real_requirement_is_accepted()
    {
        var app = BuildApp(
            authorization: o => o.AddPolicy("InvoiceOwner",
                p => p.Requirements.Add(new OwnershipRequirement())),
            map: a => a.MapGet("/api/invoices/{id}", (string id) => Results.Ok(new { id }))
                       .RequireAuthorization("InvoiceOwner"));

        Assert.Empty(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);
    }

    [Fact]
    public void A_named_policy_resolves_to_its_requirements_on_the_scanned_endpoint()
    {
        var app = BuildApp(
            authorization: o => o.AddPolicy("InvoiceOwner",
                p => p.Requirements.Add(new OwnershipRequirement())),
            map: a => a.MapGet("/api/invoices/{id}", (string id) => Results.Ok(new { id }))
                       .RequireAuthorization("InvoiceOwner"));

        var endpoint = Assert.Single(EndpointSurfaceScanner.Scan(app));

        Assert.True(endpoint.AuthorizationResolved);
        Assert.Contains("OwnershipRequirement", endpoint.PolicyRequirements);
        Assert.Contains("InvoiceOwner", endpoint.Policies);
    }

    [Fact]
    public void A_named_policy_that_cannot_be_resolved_reports_nothing_rather_than_guessing()
    {
        // Scanning a bare data source has no policy provider, so the policy is opaque.
        // An opaque policy supports no conclusion in either direction.
        var app = BuildApp(
            authorization: o => o.AddPolicy("InvoiceOwner", p => p.RequireAuthenticatedUser()),
            map: a => a.MapGet("/api/invoices/{id}", (string id) => Results.Ok(new { id }))
                       .RequireAuthorization("InvoiceOwner"));

        var source = Assert.Single(((IEndpointRouteBuilder)app).DataSources);

        var endpoint = Assert.Single(EndpointSurfaceScanner.Scan(source));
        Assert.False(endpoint.AuthorizationResolved);

        Assert.Empty(AuthorizationSurfaceAnalyzer.Analyze(EndpointSurfaceScanner.Scan(source)).Findings);
    }

    [Fact]
    public void A_role_only_named_policy_is_still_reported_as_a_role_check()
    {
        var app = BuildApp(
            authorization: o => o.AddPolicy("Admins", p => p.RequireRole("Admin")),
            map: a => a.MapGet("/api/users/{userId}", (string userId) => Results.Ok())
                       .RequireAuthorization("Admins"));

        var finding = Assert.Single(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);

        Assert.Equal(FindingCodes.RoleOnlyResourceAccess, finding.Code);
    }

    [Fact]
    public void Roles_declared_on_the_authorize_attribute_are_still_reported_as_a_role_check()
    {
        var app = BuildApp(
            map: a => a.MapGet("/api/users/{userId}", (string userId) => Results.Ok())
                       .RequireAuthorization(new AuthorizeAttribute { Roles = "Admin" }));

        var finding = Assert.Single(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);

        Assert.Equal(FindingCodes.RoleOnlyResourceAccess, finding.Code);
    }

    [Fact]
    public void A_custom_default_policy_is_honoured_for_a_bare_authorize()
    {
        // RequireAuthorization() with no arguments resolves to the default policy, so an
        // application that put a real requirement there is genuinely scoping.
        var app = BuildApp(
            authorization: o => o.DefaultPolicy = new AuthorizationPolicyBuilder()
                .AddRequirements(new OwnershipRequirement())
                .Build(),
            map: a => a.MapGet("/api/invoices/{id}", (string id) => Results.Ok(new { id }))
                       .RequireAuthorization());

        Assert.Empty(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);
    }

    // --- controllers -------------------------------------------------------------------

    private static WebApplication BuildControllerApp()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthentication();
        builder.Services.AddAuthorization();
        builder.Services.AddControllers()
            .AddApplicationPart(typeof(EffectiveAuthorizationTests).Assembly);

        var app = builder.Build();
        app.MapControllers();
        return app;
    }

    [Fact]
    public void Controller_actions_reach_the_scanner_with_their_handler_attached()
    {
        // The whole of AZP002 rests on being able to read the handler. Controller
        // endpoints arrive by a different route from minimal APIs, so if the MethodInfo
        // is missing here every controller action silently degrades to a review item.
        var endpoints = EndpointSurfaceScanner.Scan(BuildControllerApp());

        var unscoped = Assert.Single(endpoints, e => e.RoutePattern == "api/invoices/{invoiceId}");
        var scoped = Assert.Single(endpoints, e => e.RoutePattern == "api/statements/{statementId}");

        Assert.Equal(HandlerInspection.PrincipalBlind, unscoped.Handler);
        Assert.Equal(HandlerInspection.PrincipalAware, scoped.Handler);
    }

    [Fact]
    public void Controller_actions_are_classified_the_same_way_as_minimal_apis()
    {
        var report = AuthorizationSurfaceAnalyzer.Analyze(BuildControllerApp());

        var unscoped = Assert.Single(report.Findings, f => f.Code == FindingCodes.UnscopedResourceAccess);
        var scoped = Assert.Single(report.Findings, f => f.Code == FindingCodes.UnverifiedResourceAccess);

        Assert.Equal("GET /api/invoices/{invoiceId}", unscoped.Endpoint);
        Assert.Equal("GET /api/statements/{statementId}", scoped.Endpoint);
    }

    [Fact]
    public void The_sample_surface_includes_controller_endpoints()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddVulnerableApi();
        var app = builder.Build();
        app.MapVulnerableEndpoints();

        var report = AuthorizationSurfaceAnalyzer.Analyze(app);
        var flagged = report.Findings.Select(f => f.Endpoint).ToList();

        Assert.Contains("GET /api/orders/{orderId}", flagged);
        Assert.Contains("GET /api/receipts/{receiptId}", flagged);
    }

    // --- the service provider overload -------------------------------------------------

    [Fact]
    public async Task Scanning_through_the_service_provider_resolves_policies_too()
    {
        var app = BuildApp(
            authorization: o => o.AddPolicy("MustOwnTheRecord", p => p.RequireAuthenticatedUser()),
            map: a => a.MapGet("/api/invoices/{id}", (string id) => Results.Ok(new { id }))
                       .RequireAuthorization("MustOwnTheRecord"));

        // Force the composite data source to be built, as running the app would.
        await app.StartAsync();

        try
        {
            var endpoints = EndpointSurfaceScanner.Scan(app.Services);

            var endpoint = Assert.Single(endpoints, e => e.RoutePattern == "/api/invoices/{id}");
            Assert.True(endpoint.AuthorizationResolved);
            Assert.False(endpoint.HasSubstantiveRequirement);
        }
        finally
        {
            await app.StopAsync();
        }
    }
}

/// <summary>
/// Controllers must be top-level public types: MVC's discovery requires <c>Type.IsPublic</c>,
/// which a nested type never satisfies.
/// </summary>
[ApiController]
[Authorize]
[Route("api")]
public sealed class TestInvoicesController : ControllerBase
{
    [HttpGet("invoices/{invoiceId}")]
    public IActionResult Unscoped(string invoiceId) => Ok(new { invoiceId });

    [HttpGet("statements/{statementId}")]
    public IActionResult Scoped(string statementId) =>
        Ok(new { statementId, who = User.FindFirstValue(ClaimTypes.NameIdentifier) });
}

/// <summary>
/// A stock MVC or Blazor application registers one endpoint per static file. Reporting
/// them buries the findings that matter, so they are excluded by default.
/// </summary>
public class InfrastructureEndpointTests
{
    private sealed record FakeAsset(string Route);

    private static HttpEndpointInfo StaticAsset(string route) => new()
    {
        DisplayName = route,
        RoutePattern = route,
        HttpMethods = ["GET", "HEAD"],
        IsInfrastructureEndpoint = true
    };

    private static HttpEndpointInfo ApiEndpoint(string route) => new()
    {
        DisplayName = route,
        RoutePattern = route,
        HttpMethods = ["GET"]
    };

    [Fact]
    public void Static_asset_endpoints_are_excluded_by_default()
    {
        var report = AuthorizationSurfaceAnalyzer.Analyze(
        [
            StaticAsset("css/site.css"),
            StaticAsset("lib/bootstrap/dist/css/bootstrap.css"),
            ApiEndpoint("api/reports/export")
        ]);

        var finding = Assert.Single(report.Findings);
        Assert.Equal(FindingCodes.ImplicitlyAnonymous, finding.Code);
        Assert.Equal("GET /api/reports/export", finding.Endpoint);
    }

    [Fact]
    public void Excluded_endpoints_are_left_out_of_the_analysed_count()
    {
        var report = AuthorizationSurfaceAnalyzer.Analyze(
        [
            StaticAsset("css/site.css"),
            ApiEndpoint("api/reports/export")
        ]);

        Assert.Single(report.Endpoints);
        Assert.Contains("Endpoints analysed: **1**", report.ToMarkdown());
    }

    [Fact]
    public void Static_asset_endpoints_can_be_opted_back_in()
    {
        var options = new AuthzProbeOptions { IncludeInfrastructureEndpoints = true };

        var report = AuthorizationSurfaceAnalyzer.Analyze([StaticAsset("css/site.css")], options);

        Assert.Single(report.Findings);
    }

    [Fact]
    public void Openapi_document_endpoints_are_ignored_by_default()
    {
        var report = AuthorizationSurfaceAnalyzer.Analyze([ApiEndpoint("openapi/{documentName}.json")]);

        Assert.Empty(report.Findings);
    }
}
