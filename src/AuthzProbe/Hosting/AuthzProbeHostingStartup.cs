using AuthzProbe.Analysis;
using AuthzProbe.Hosting;
using AuthzProbe.Model;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

[assembly: HostingStartup(typeof(AuthzProbeHostingStartup))]

namespace AuthzProbe.Hosting;

/// <summary>
/// Runs the probe against an application without changing a line of its source.
/// </summary>
/// <remarks>
/// <para>
/// A hosting startup assembly is loaded only when it is named in
/// <c>ASPNETCORE_HOSTINGSTARTUPASSEMBLIES</c>, so adding the package changes nothing on its
/// own. Set the variable and the probe attaches to the running application, reads the routing
/// table the framework actually built, and writes its report:
/// </para>
/// <code>
/// ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=AuthzProbe \
/// AUTHZPROBE_EXIT=1 \
/// dotnet run --project ./YourApi
/// </code>
/// <para>
/// This is why AuthzProbe reads a live routing table rather than analysing source: conventions
/// applied globally, policies registered by name, and the fallback policy are all decided at
/// runtime, and an application you have not modified is the most honest thing to measure.
/// </para>
/// </remarks>
public sealed class AuthzProbeHostingStartup : IHostingStartup
{
    /// <summary>Registers the reporter that probes the application once it has started.</summary>
    public void Configure(IWebHostBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ConfigureServices(services => services.AddHostedService<AuthzProbeReporter>());
    }
}

/// <summary>
/// Probes the application at <c>ApplicationStarted</c>, which is the first moment the composite
/// endpoint data source holds every endpoint the application will serve.
/// </summary>
internal sealed class AuthzProbeReporter : IHostedService
{
    private readonly IServiceProvider _services;
    private readonly IHostApplicationLifetime _lifetime;

    public AuthzProbeReporter(IServiceProvider services, IHostApplicationLifetime lifetime)
    {
        _services = services;
        _lifetime = lifetime;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _lifetime.ApplicationStarted.Register(Probe);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private void Probe()
    {
        try
        {
            var options = new AuthzProbeOptions();

            if (Enum.TryParse<FindingSeverity>(Read("AUTHZPROBE_FAIL_ON"), ignoreCase: true, out var failOn))
            {
                options.FailOn = failOn;
            }

            if (string.Equals(Read("AUTHZPROBE_INCLUDE_INFRASTRUCTURE"), "1", StringComparison.Ordinal))
            {
                options.IncludeInfrastructureEndpoints = true;
            }

            var report = AuthorizationSurfaceAnalyzer.Analyze(_services, options);
            var markdown = report.ToMarkdown();

            Console.WriteLine(markdown);

            if (Read("AUTHZPROBE_REPORT_PATH") is { Length: > 0 } path)
            {
                File.WriteAllText(path, markdown);
            }

            if (string.Equals(Read("AUTHZPROBE_EXIT"), "1", StringComparison.Ordinal))
            {
                Environment.ExitCode = report.Passed ? 0 : 1;
                _lifetime.StopApplication();
            }
        }
        catch (Exception ex)
        {
            // Attaching to somebody else's application must never be what takes it down.
            Console.Error.WriteLine($"AuthzProbe failed to probe this application: {ex}");

            if (string.Equals(Read("AUTHZPROBE_EXIT"), "1", StringComparison.Ordinal))
            {
                Environment.ExitCode = 2;
                _lifetime.StopApplication();
            }
        }
    }

    private static string? Read(string name) => Environment.GetEnvironmentVariable(name);
}
