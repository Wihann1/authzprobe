using AuthzProbe.Analysis;
using AuthzProbe.Model;
using AuthzProbe.Scanning;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using SampleApi;

namespace AuthzProbe.Tests;

public class AuthorizationSurfaceAnalyzerTests
{
    private static WebApplication BuildSampleApp()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddVulnerableApi();

        var app = builder.Build();
        app.MapVulnerableEndpoints();
        return app;
    }

    private static AuthorizationSurfaceReport AnalyzeSample(AuthzProbeOptions? options = null)
    {
        var app = BuildSampleApp();
        return AuthorizationSurfaceAnalyzer.Analyze(app, options);
    }

    private static IEnumerable<string> EndpointsFlagged(AuthorizationSurfaceReport report, string code) =>
        report.Findings.Where(f => f.Code == code).Select(f => f.Endpoint!);

    [Fact]
    public void Scans_every_mapped_endpoint()
    {
        var app = BuildSampleApp();

        var endpoints = EndpointSurfaceScanner.Scan(app);

        Assert.Equal(13, endpoints.Count);
    }

    [Fact]
    public void Flags_endpoint_with_no_authorization_metadata_as_error()
    {
        var report = AnalyzeSample();

        var finding = Assert.Single(report.Findings, f => f.Code == FindingCodes.ImplicitlyAnonymous);
        Assert.Equal(FindingSeverity.Error, finding.Severity);
        Assert.Equal("GET /api/reports/export", finding.Endpoint);
    }

    [Fact]
    public void Flags_object_addressing_endpoints_that_only_require_authentication()
    {
        var report = AnalyzeSample();

        var flagged = EndpointsFlagged(report, FindingCodes.UnscopedResourceAccess).ToList();

        Assert.Contains("GET /api/invoices/{id:guid}", flagged);
        Assert.Contains("GET /api/tenants/{tenantId}/documents/{documentId}", flagged);
        Assert.Equal(4, flagged.Count);
    }

    [Fact]
    public void Does_not_flag_authenticated_endpoint_without_a_resource_identifier()
    {
        var report = AnalyzeSample();

        Assert.DoesNotContain("GET /api/me", report.Findings.Select(f => f.Endpoint));
    }

    [Fact]
    public void Does_not_flag_endpoint_protected_by_a_named_policy()
    {
        var report = AnalyzeSample();

        Assert.DoesNotContain("GET /api/secure-invoices/{id:guid}", report.Findings.Select(f => f.Endpoint));
    }

    [Fact]
    public void Downgrades_to_review_when_the_handler_reads_the_principal()
    {
        // The handler takes HttpContext and reads ctx.User, so it may be scoping
        // ownership in its body. That is a review item, not a defect.
        var report = AnalyzeSample();

        var flagged = EndpointsFlagged(report, FindingCodes.UnverifiedResourceAccess).ToList();

        Assert.Contains("GET /api/statements/{statementId}", flagged);
        Assert.All(
            report.Findings.Where(f => f.Code == FindingCodes.UnverifiedResourceAccess),
            f => Assert.Equal(FindingSeverity.Info, f.Severity));
    }

    [Fact]
    public void Handler_that_reads_the_principal_is_detected_as_principal_aware()
    {
        var app = BuildSampleApp();

        var endpoint = EndpointSurfaceScanner.Scan(app)
            .Single(e => e.RoutePattern == "/api/statements/{statementId}");

        Assert.Equal(HandlerInspection.PrincipalAware, endpoint.Handler);
    }

    [Fact]
    public void Handler_that_ignores_the_principal_is_detected_as_principal_blind()
    {
        var app = BuildSampleApp();

        var endpoint = EndpointSurfaceScanner.Scan(app)
            .Single(e => e.RoutePattern == "/api/invoices/{id:guid}");

        Assert.Equal(HandlerInspection.PrincipalBlind, endpoint.Handler);
    }

    [Fact]
    public void An_uninspectable_handler_is_reported_for_review_not_as_a_defect()
    {
        // Unknown is not evidence of absence. Claiming AZP002 here would present a
        // possibly-safe endpoint as a confirmed authorization defect.
        var endpoint = new HttpEndpointInfo
        {
            DisplayName = "GET /api/things/{id}",
            RoutePattern = "api/things/{id}",
            HttpMethods = ["GET"],
            RequiresAuthorization = true,
            ExposesResourceIdentifier = true,
            RouteParameters = ["id"],
            Handler = HandlerInspection.Unknown
        };

        var report = AuthorizationSurfaceAnalyzer.Analyze([endpoint]);

        var finding = Assert.Single(report.Findings);
        Assert.Equal(FindingCodes.UnverifiedResourceAccess, finding.Code);
        Assert.Equal(FindingSeverity.Info, finding.Severity);
    }

    [Fact]
    public void A_principal_blind_handler_is_reported_as_a_defect()
    {
        var endpoint = new HttpEndpointInfo
        {
            DisplayName = "GET /api/things/{id}",
            RoutePattern = "api/things/{id}",
            HttpMethods = ["GET"],
            RequiresAuthorization = true,
            ExposesResourceIdentifier = true,
            RouteParameters = ["id"],
            Handler = HandlerInspection.PrincipalBlind
        };

        var report = AuthorizationSurfaceAnalyzer.Analyze([endpoint]);

        var finding = Assert.Single(report.Findings);
        Assert.Equal(FindingCodes.UnscopedResourceAccess, finding.Code);
        Assert.Equal(FindingSeverity.Warning, finding.Severity);
    }

    [Fact]
    public void Does_not_treat_pagination_parameters_as_resource_identifiers()
    {
        var report = AnalyzeSample();

        Assert.DoesNotContain("GET /api/invoices", report.Findings.Select(f => f.Endpoint));
    }

    [Fact]
    public void Flags_anonymous_endpoint_that_addresses_an_object()
    {
        var report = AnalyzeSample();

        var finding = Assert.Single(report.Findings, f => f.Code == FindingCodes.AnonymousResourceAccess);
        Assert.Equal("GET /api/payslips/{payslipId}", finding.Endpoint);
    }

    [Fact]
    public void Detects_roles_configured_through_an_inline_policy()
    {
        // RequireAuthorization(p => p.RequireRole(...)) compiles the role into an
        // AuthorizationPolicy, so it never appears on IAuthorizeData.Roles.
        var report = AnalyzeSample();

        var finding = Assert.Single(report.Findings, f => f.Code == FindingCodes.RoleOnlyResourceAccess);
        Assert.Equal("GET /api/admin/users/{userId}", finding.Endpoint);
    }

    [Fact]
    public void Ignores_health_endpoints_by_default()
    {
        var report = AnalyzeSample();

        Assert.DoesNotContain("/health", report.Findings.Select(f => f.Endpoint ?? string.Empty));
    }

    [Fact]
    public void Fails_by_default_because_of_the_unprotected_endpoint()
    {
        var report = AnalyzeSample();

        Assert.False(report.Passed);
        Assert.Throws<AuthzProbeException>(report.ThrowIfFailed);
    }

    [Fact]
    public void Passes_when_only_warnings_are_present_and_the_error_is_suppressed()
    {
        var options = new AuthzProbeOptions();
        options.SuppressedCodes.Add(FindingCodes.ImplicitlyAnonymous);

        var report = AnalyzeSample(options);

        Assert.True(report.Passed);
        report.ThrowIfFailed();
    }

    [Fact]
    public void Escalates_unscoped_resource_access_to_error_when_configured()
    {
        var options = new AuthzProbeOptions { TreatUnscopedResourceAccessAsError = true };

        var report = AnalyzeSample(options);

        Assert.All(
            report.Findings.Where(f => f.Code == FindingCodes.UnscopedResourceAccess),
            f => Assert.Equal(FindingSeverity.Error, f.Severity));
    }

    [Fact]
    public void Report_renders_the_findings_as_markdown()
    {
        var report = AnalyzeSample();

        var markdown = report.ToMarkdown();

        Assert.Contains("# AuthzProbe report", markdown);
        Assert.Contains("Endpoints analysed: **12**", markdown);
        Assert.Contains(FindingCodes.UnscopedResourceAccess, markdown);
        Assert.Contains("**FAIL**", markdown);
    }
}
