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
        builder.Services.AddAuthentication();
        builder.Services.AddAuthorization(options =>
            options.AddPolicy("InvoiceOwner", policy => policy.RequireAuthenticatedUser()));

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

        Assert.Equal(9, endpoints.Count);
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
        Assert.Equal(2, flagged.Count);
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
        Assert.Contains("Endpoints scanned: **9**", markdown);
        Assert.Contains(FindingCodes.UnscopedResourceAccess, markdown);
        Assert.Contains("**FAIL**", markdown);
    }
}
