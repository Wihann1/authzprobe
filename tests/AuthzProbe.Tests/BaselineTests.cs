using AuthzProbe.Analysis;
using AuthzProbe.Model;

namespace AuthzProbe.Tests;

/// <summary>
/// A tool that reports two hundred findings the day it is installed gets uninstalled. The
/// baseline is the ratchet that makes adoption possible.
/// </summary>
public class BaselineTests
{
    private static HttpEndpointInfo Unscoped(string route) => new()
    {
        DisplayName = route,
        RoutePattern = route,
        HttpMethods = ["GET"],
        RequiresAuthorization = true,
        ExposesResourceIdentifier = true,
        RouteParameters = ["id"],
        Handler = HandlerInspection.PrincipalBlind
    };

    private static AuthorizationSurfaceReport Analyze(
        IReadOnlyList<HttpEndpointInfo> endpoints,
        AuthzProbeBaseline? baseline = null)
    {
        var options = new AuthzProbeOptions
        {
            Baseline = baseline,
            TreatUnscopedResourceAccessAsError = true
        };

        return AuthorizationSurfaceAnalyzer.Analyze(endpoints, options);
    }

    [Fact]
    public void Without_a_baseline_every_finding_counts()
    {
        var report = Analyze([Unscoped("api/a/{id}"), Unscoped("api/b/{id}")]);

        Assert.Equal(2, report.Findings.Count);
        Assert.False(report.Passed);
    }

    [Fact]
    public void A_baseline_forgives_what_the_codebase_already_had()
    {
        var existing = Analyze([Unscoped("api/a/{id}"), Unscoped("api/b/{id}")]);
        var baseline = existing.ToBaseline();

        var report = Analyze([Unscoped("api/a/{id}"), Unscoped("api/b/{id}")], baseline);

        Assert.Empty(report.Findings);
        Assert.Equal(2, report.BaselinedFindings.Count);
        Assert.True(report.Passed);
    }

    [Fact]
    public void A_new_gap_fails_even_when_the_old_ones_are_forgiven()
    {
        var baseline = Analyze([Unscoped("api/a/{id}")]).ToBaseline();

        var report = Analyze([Unscoped("api/a/{id}"), Unscoped("api/b/{id}")], baseline);

        var finding = Assert.Single(report.Findings);
        Assert.Equal("GET /api/b/{id}", finding.Endpoint);
        Assert.False(report.Passed);
    }

    [Fact]
    public void A_fixed_gap_is_reported_as_a_stale_baseline_entry()
    {
        // Left in place, the entry would silently forgive the same defect if it came back.
        var baseline = Analyze([Unscoped("api/a/{id}"), Unscoped("api/b/{id}")]).ToBaseline();

        var report = Analyze([Unscoped("api/a/{id}")], baseline);

        var stale = Assert.Single(report.StaleBaselineEntries);
        Assert.Equal("AZP002 GET /api/b/{id}", stale);
        Assert.True(report.Passed);
    }

    [Fact]
    public void The_report_says_what_the_baseline_forgave()
    {
        var baseline = Analyze([Unscoped("api/a/{id}")]).ToBaseline();

        var markdown = Analyze([Unscoped("api/a/{id}")], baseline).ToMarkdown();

        Assert.Contains("Baselined: **1**", markdown);
        Assert.Contains("No new authorization gaps detected.", markdown);
    }

    [Fact]
    public void The_file_round_trips_and_is_sorted()
    {
        var baseline = Analyze([Unscoped("api/z/{id}"), Unscoped("api/a/{id}")]).ToBaseline();

        var content = baseline.ToFileContent();
        var reloaded = AuthzProbeBaseline.Parse(content.Split('\n'));

        Assert.Equal(baseline.Entries, reloaded.Entries);
        Assert.Equal(reloaded.Entries.OrderBy(e => e, StringComparer.Ordinal), reloaded.Entries);
        Assert.Contains("# AuthzProbe baseline", content);
    }

    [Fact]
    public void Comments_and_blank_lines_are_ignored_when_reading()
    {
        var baseline = AuthzProbeBaseline.Parse(["# a comment", "", "  AZP002 GET /api/a/{id}  "]);

        var report = Analyze([Unscoped("api/a/{id}")], baseline);

        Assert.Empty(report.Findings);
        Assert.Single(report.BaselinedFindings);
    }

    [Fact]
    public void A_missing_baseline_file_is_an_empty_baseline()
    {
        var baseline = AuthzProbeBaseline.Load(Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.txt"));

        Assert.Empty(baseline.Entries);
    }

    [Fact]
    public void A_baseline_written_to_disk_reads_back()
    {
        var path = Path.Combine(Path.GetTempPath(), $"authzprobe-baseline-{Guid.NewGuid():N}.txt");

        try
        {
            File.WriteAllText(path, Analyze([Unscoped("api/a/{id}")]).ToBaseline().ToFileContent());

            var report = Analyze([Unscoped("api/a/{id}")], AuthzProbeBaseline.Load(path));

            Assert.Empty(report.Findings);
            Assert.True(report.Passed);
        }
        finally
        {
            File.Delete(path);
        }
    }
}

/// <summary>
/// nopCommerce enforces access with its own MVC permission filters and never calls
/// AddAuthorization, so a literal reading of its routing table produced 1,675 findings on
/// 1,675 endpoints. Every one was true and the report was worthless.
/// </summary>
public class WholeSurfaceUnprotectedTests
{
    private static IReadOnlyList<HttpEndpointInfo> Surface(int count, int protectedCount = 0) =>
        Enumerable.Range(0, count)
            .Select(i => new HttpEndpointInfo
            {
                DisplayName = $"api/thing{i}",
                RoutePattern = $"api/thing{i}",
                HttpMethods = ["GET"],
                RequiresAuthorization = i < protectedCount
            })
            .ToArray();

    [Fact]
    public void A_wholly_unprotected_surface_is_reported_once()
    {
        var report = AuthorizationSurfaceAnalyzer.Analyze(Surface(1675));

        var finding = Assert.Single(report.Findings);
        Assert.Equal(FindingCodes.AuthorizationNotObservable, finding.Code);
        Assert.Equal(FindingSeverity.Error, finding.Severity);
        Assert.Contains("1675 of 1675", finding.Evidence);
        Assert.False(report.Passed);
    }

    [Fact]
    public void A_small_surface_is_still_reported_endpoint_by_endpoint()
    {
        // Below the threshold an absence of metadata is not evidence of a pattern, and the
        // per-endpoint list is what someone can act on.
        var report = AuthorizationSurfaceAnalyzer.Analyze(Surface(5));

        Assert.Equal(5, report.Findings.Count);
        Assert.All(report.Findings, f => Assert.Equal(FindingCodes.ImplicitlyAnonymous, f.Code));
    }

    [Fact]
    public void A_surface_with_real_authorization_keeps_its_individual_findings()
    {
        // A tenth of the endpoints are protected, so the application clearly does use
        // ASP.NET Core authorization and the unprotected ones are genuine findings.
        var report = AuthorizationSurfaceAnalyzer.Analyze(Surface(100, protectedCount: 10));

        Assert.Equal(90, report.Findings.Count);
        Assert.All(report.Findings, f => Assert.Equal(FindingCodes.ImplicitlyAnonymous, f.Code));
    }

    [Fact]
    public void The_collapse_can_be_suppressed_like_any_other_code()
    {
        var options = new AuthzProbeOptions();
        options.SuppressedCodes.Add(FindingCodes.AuthorizationNotObservable);

        var report = AuthorizationSurfaceAnalyzer.Analyze(Surface(100), options);

        Assert.Equal(100, report.Findings.Count);
    }
}
