using System.Text;
using AuthzProbe.Model;

namespace AuthzProbe.Analysis;

/// <summary>
/// The findings an existing codebase already has, so only new ones fail the build.
/// </summary>
/// <remarks>
/// <para>
/// A tool that reports two hundred findings the day it is installed gets uninstalled. A
/// baseline is the ratchet: record today's surface, fail on anything added to it, and let the
/// existing debt be paid down deliberately rather than all at once.
/// </para>
/// <para>
/// The file is one finding per line — <c>AZP002 GET /api/invoices/{id}</c> — sorted, so it
/// diffs cleanly in review and a pull request that adds a line is visibly adding an
/// authorization gap.
/// </para>
/// </remarks>
public sealed class AuthzProbeBaseline
{
    private readonly HashSet<string> _entries;

    private AuthzProbeBaseline(IEnumerable<string> entries) =>
        _entries = new HashSet<string>(entries, StringComparer.Ordinal);

    /// <summary>Every entry, sorted.</summary>
    public IReadOnlyList<string> Entries => _entries.OrderBy(e => e, StringComparer.Ordinal).ToArray();

    /// <summary>An empty baseline: nothing is forgiven.</summary>
    public static AuthzProbeBaseline Empty { get; } = new([]);

    /// <summary>Reads a baseline file. A missing file is an empty baseline.</summary>
    public static AuthzProbeBaseline Load(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        return File.Exists(path)
            ? Parse(File.ReadAllLines(path))
            : Empty;
    }

    /// <summary>Reads a baseline from lines already in hand.</summary>
    public static AuthzProbeBaseline Parse(IEnumerable<string> lines)
    {
        ArgumentNullException.ThrowIfNull(lines);

        return new AuthzProbeBaseline(lines
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith('#')));
    }

    /// <summary>Builds a baseline covering exactly these findings.</summary>
    public static AuthzProbeBaseline FromFindings(IEnumerable<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        return new AuthzProbeBaseline(findings.Select(KeyFor));
    }

    /// <summary>True when this finding is already recorded and should not fail the build.</summary>
    public bool Covers(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        return _entries.Contains(KeyFor(finding));
    }

    /// <summary>
    /// Entries that no longer match any finding — gaps that have since been closed. Removing
    /// them keeps the baseline from silently forgiving a defect that comes back.
    /// </summary>
    public IReadOnlyList<string> StaleEntries(IEnumerable<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var live = new HashSet<string>(findings.Select(KeyFor), StringComparer.Ordinal);

        return _entries.Where(e => !live.Contains(e)).OrderBy(e => e, StringComparer.Ordinal).ToArray();
    }

    /// <summary>Renders the file, ready to commit.</summary>
    public string ToFileContent()
    {
        var sb = new StringBuilder();
        sb.AppendLine("# AuthzProbe baseline — the authorization gaps this codebase already had.");
        sb.AppendLine("#");
        sb.AppendLine("# Findings listed here do not fail the build. Anything not listed does, so a pull");
        sb.AppendLine("# request that adds a line here is visibly adding an authorization gap.");
        sb.AppendLine("# Delete lines as you fix them; never regenerate the file to make a build pass.");
        sb.AppendLine();

        foreach (var entry in Entries)
        {
            sb.AppendLine(entry);
        }

        return sb.ToString();
    }

    private static string KeyFor(Finding finding) =>
        finding.Endpoint is null ? finding.Code : $"{finding.Code} {finding.Endpoint}";
}
