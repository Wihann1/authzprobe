using AuthzProbe.Analysis;
using SampleApi;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication();
builder.Services.AddAuthorization(options =>
{
    // Stands in for a real resource-based policy.
    options.AddPolicy("InvoiceOwner", policy => policy.RequireAuthenticatedUser());
});

var app = builder.Build();

app.MapVulnerableEndpoints();

// Run the probe at startup and print the report. In CI you would call
// report.ThrowIfFailed() instead, and let a non-zero exit fail the build.
var report = AuthorizationSurfaceAnalyzer.Analyze(app);
Console.WriteLine(report.ToMarkdown());

if (args.Contains("--probe-only"))
{
    return report.Passed ? 0 : 1;
}

app.Run();
return 0;
