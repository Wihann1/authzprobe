using System.Text;
using AuthzProbe.Model;

namespace AuthzProbe.Analysis;

/// <summary>The result of analysing an application's authorization surface.</summary>
public sealed class AuthorizationSurfaceReport
{
    /// <summary>Creates a report over a scanned surface and the findings raised against it.</summary>
    /// <param name="endpoints">Every endpoint that was analysed.</param>
    /// <param name="findings">Findings raised, in discovery order.</param>
    /// <param name="failOn">Minimum severity treated as a failure.</param>
    /// <param name="baselinedFindings">Findings forgiven by the baseline.</param>
    /// <param name="staleBaselineEntries">Baseline entries that no longer match any finding.</param>
    public AuthorizationSurfaceReport(
        IReadOnlyList<HttpEndpointInfo> endpoints,
        IReadOnlyList<Finding> findings,
        FindingSeverity failOn,
        IReadOnlyList<Finding>? baselinedFindings = null,
        IReadOnlyList<string>? staleBaselineEntries = null)
    {
        Endpoints = endpoints;
        Findings = findings;
        FailOn = failOn;
        BaselinedFindings = baselinedFindings ?? [];
        StaleBaselineEntries = staleBaselineEntries ?? [];
    }

    /// <summary>
    /// Every endpoint that was analysed, including those that raised nothing. Endpoints
    /// excluded by <see cref="AuthzProbeOptions.IgnoredRoutePatterns"/>, and static-asset
    /// and fallback endpoints, are not included.
    /// </summary>
    public IReadOnlyList<HttpEndpointInfo> Endpoints { get; }

    /// <summary>All findings raised, at every severity.</summary>
    public IReadOnlyList<Finding> Findings { get; }

    /// <summary>Minimum severity treated as a failure.</summary>
    public FindingSeverity FailOn { get; }

    /// <summary>
    /// Findings the baseline forgives. They are real, and they do not fail the build.
    /// </summary>
    public IReadOnlyList<Finding> BaselinedFindings { get; }

    /// <summary>
    /// Baseline entries matching nothing in this run — gaps since closed. Delete them, or the
    /// baseline will silently forgive the same defect if it returns.
    /// </summary>
    public IReadOnlyList<string> StaleBaselineEntries { get; }

    /// <summary>The baseline this run would write: every finding, forgiven or not.</summary>
    public AuthzProbeBaseline ToBaseline() =>
        AuthzProbeBaseline.FromFindings(Findings.Concat(BaselinedFindings));

    /// <summary>The subset of <see cref="Findings"/> that meet the fail threshold.</summary>
    public IEnumerable<Finding> Failures => Findings.Where(f => f.Severity >= FailOn);

    /// <summary>True when nothing met the fail threshold.</summary>
    public bool Passed => !Failures.Any();

    /// <summary>Throws with a readable summary when any finding meets the fail threshold.</summary>
    public void ThrowIfFailed()
    {
        if (Passed)
        {
            return;
        }

        throw new AuthzProbeException(ToMarkdown());
    }

    /// <summary>A report suitable for CI output, a PR comment, or pentest evidence.</summary>
    public string ToMarkdown()
    {
        var sb = new StringBuilder();
        sb.AppendLine("# AuthzProbe report");
        sb.AppendLine();
        sb.AppendLine($"- Endpoints analysed: **{Endpoints.Count}**");
        sb.AppendLine($"- Findings: **{Findings.Count}** "
                      + $"({Findings.Count(f => f.Severity == FindingSeverity.Error)} error, "
                      + $"{Findings.Count(f => f.Severity == FindingSeverity.Warning)} warning, "
                      + $"{Findings.Count(f => f.Severity == FindingSeverity.Info)} info)");
        if (BaselinedFindings.Count > 0)
        {
            sb.AppendLine($"- Baselined: **{BaselinedFindings.Count}** (already recorded, not failing the build)");
        }

        if (StaleBaselineEntries.Count > 0)
        {
            sb.AppendLine($"- Stale baseline entries: **{StaleBaselineEntries.Count}** "
                          + "(fixed since — delete them from the baseline)");
        }

        sb.AppendLine($"- Result: **{(Passed ? "PASS" : "FAIL")}**");
        sb.AppendLine();

        if (Findings.Count == 0)
        {
            sb.AppendLine(BaselinedFindings.Count > 0
                ? "No new authorization gaps detected."
                : "No authorization gaps detected.");

            AppendStaleEntries(sb);
            return sb.ToString();
        }

        foreach (var group in Findings.GroupBy(f => f.Code).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            var first = group.First();
            sb.AppendLine($"## {group.Key} — {first.Title} ({group.Count()})");
            sb.AppendLine();
            sb.AppendLine(first.Detail);
            sb.AppendLine();

            foreach (var finding in group)
            {
                sb.AppendLine(finding.Evidence is null
                    ? $"- `{finding.Endpoint}`"
                    : $"- `{finding.Endpoint}` — {finding.Evidence}");
            }

            if (first.Remediation is not null)
            {
                sb.AppendLine();
                sb.AppendLine($"**Fix:** {first.Remediation}");
            }

            sb.AppendLine();
        }

        AppendStaleEntries(sb);

        return sb.ToString();
    }

    private void AppendStaleEntries(StringBuilder sb)
    {
        if (StaleBaselineEntries.Count == 0)
        {
            return;
        }

        sb.AppendLine();
        sb.AppendLine("## Stale baseline entries");
        sb.AppendLine();
        sb.AppendLine("These were fixed. Remove them from the baseline so the gap cannot return unnoticed.");
        sb.AppendLine();

        foreach (var entry in StaleBaselineEntries)
        {
            sb.AppendLine($"- `{entry}`");
        }

        sb.AppendLine();
    }
}

/// <summary>Thrown when the authorization surface fails the configured threshold.</summary>
public sealed class AuthzProbeException : Exception
{
    /// <summary>Creates the exception with a rendered report as its message.</summary>
    /// <param name="message">The rendered report.</param>
    public AuthzProbeException(string message) : base(message)
    {
    }
}
