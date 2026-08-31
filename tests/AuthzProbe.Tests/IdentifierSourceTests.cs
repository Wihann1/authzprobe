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

namespace AuthzProbe.Tests;

/// <summary>
/// An identifier in the query string or the request body addresses an object exactly as a
/// route identifier does. Only the route one is visible in a route template.
/// </summary>
public class IdentifierSourceTests
{
    public sealed record UpdateInvoiceRequest
    {
        public string InvoiceId { get; init; } = "";
        public decimal Amount { get; init; }
    }

    public sealed record CreateNoteRequest
    {
        public string Text { get; init; } = "";
    }

    public interface INotesRepository
    {
        string Get(string id);
    }

    private sealed class NotesRepository : INotesRepository
    {
        public string Get(string id) => id;
    }

    private static WebApplication Build(Action<IEndpointRouteBuilder> map, Action<AuthorizationOptions>? authz = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthentication();
        builder.Services.AddAuthorization(o => authz?.Invoke(o));
        builder.Services.AddSingleton<INotesRepository, NotesRepository>();
        var app = builder.Build();
        map(app);
        return app;
    }

    // --- query string ------------------------------------------------------------------

    [Fact]
    public void An_identifier_in_the_query_string_addresses_an_object()
    {
        var app = Build(a => a.MapGet("/api/invoices", (string invoiceId) => Results.Ok(new { invoiceId }))
                              .RequireAuthorization());

        var endpoint = Assert.Single(EndpointSurfaceScanner.Scan(app));

        Assert.True(endpoint.ExposesResourceIdentifier);
        Assert.Contains("invoiceId", endpoint.QueryIdentifiers);

        var finding = Assert.Single(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);
        Assert.Equal(FindingCodes.UnscopedResourceAccess, finding.Code);
    }

    [Fact]
    public void Pagination_parameters_are_still_not_identifiers()
    {
        var app = Build(a => a.MapGet("/api/invoices", (int page, int pageSize) => Results.Ok())
                              .RequireAuthorization());

        Assert.Empty(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);
    }

    [Fact]
    public void An_injected_service_is_not_mistaken_for_a_request_value()
    {
        // Registered, as it would be in a real application — ASP.NET Core itself refuses to
        // bind an unregistered interface, inferring it as a body parameter instead.
        var app = Build(a => a.MapGet("/api/notes", (INotesRepository repo) => Results.Ok())
                              .RequireAuthorization());

        var endpoint = Assert.Single(EndpointSurfaceScanner.Scan(app));

        Assert.Empty(endpoint.QueryIdentifiers);
        Assert.Empty(endpoint.BodyIdentifiers);
    }

    [Fact]
    public void A_route_bound_parameter_is_not_counted_twice()
    {
        var app = Build(a => a.MapGet("/api/invoices/{invoiceId}", (string invoiceId) => Results.Ok())
                              .RequireAuthorization());

        var endpoint = Assert.Single(EndpointSurfaceScanner.Scan(app));

        Assert.Contains("invoiceId", endpoint.RouteParameters);
        Assert.Empty(endpoint.QueryIdentifiers);
    }

    // --- request body ------------------------------------------------------------------

    [Fact]
    public void An_identifier_in_the_body_is_reported_for_review()
    {
        // This is the eShopOnWeb shape: PUT /api/catalog-items, role-guarded, with the item's
        // identifier in the body. The route template shows nothing at all.
        var app = Build(
            a => a.MapPut("/api/invoices", (UpdateInvoiceRequest request) => Results.Ok())
                  .RequireAuthorization(new AuthorizeAttribute { Roles = "Admin" }));

        var endpoint = Assert.Single(EndpointSurfaceScanner.Scan(app));
        Assert.Contains("InvoiceId", endpoint.BodyIdentifiers);
        Assert.False(endpoint.ExposesResourceIdentifier);

        var finding = Assert.Single(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);
        Assert.Equal(FindingCodes.BodyResourceAccess, finding.Code);
        Assert.Equal(FindingSeverity.Info, finding.Severity);

        // The identifier names are true of this endpoint only, so they must ride on the
        // finding rather than the shared per-code detail the report groups under.
        Assert.Contains("InvoiceId", finding.Evidence);
        Assert.DoesNotContain("InvoiceId", finding.Detail);
    }

    [Fact]
    public void Two_endpoints_under_one_code_keep_their_own_identifiers()
    {
        // The report groups findings by code and prints one shared detail. Endpoint-specific
        // text in that detail would be attributed to every endpoint in the group.
        var app = Build(a =>
        {
            a.MapPut("/api/invoices", (UpdateInvoiceRequest request) => Results.Ok())
             .RequireAuthorization();
            a.MapPut("/api/orders", (UpdateOrderRequest request) => Results.Ok())
             .RequireAuthorization();
        });

        var report = AuthorizationSurfaceAnalyzer.Analyze(app);
        var markdown = report.ToMarkdown();

        Assert.Equal(2, report.Findings.Count(f => f.Code == FindingCodes.BodyResourceAccess));
        Assert.Contains("`PUT /api/invoices` — binds InvoiceId", markdown);
        Assert.Contains("`PUT /api/orders` — binds OrderId", markdown);
    }

    public sealed record UpdateOrderRequest
    {
        public string OrderId { get; init; } = "";
    }

    [Fact]
    public void A_body_without_an_identifier_raises_nothing()
    {
        var app = Build(a => a.MapPost("/api/notes", (CreateNoteRequest request) => Results.Ok())
                              .RequireAuthorization());

        Assert.Empty(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);
    }

    [Fact]
    public void A_body_identifier_is_not_reported_when_a_resource_policy_scopes_it()
    {
        var app = Build(
            a => a.MapPut("/api/invoices", (UpdateInvoiceRequest request) => Results.Ok())
                  .RequireAuthorization("InvoiceOwner"),
            o => o.AddPolicy("InvoiceOwner", p => p.Requirements.Add(new OwnershipRequirement())));

        Assert.Empty(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);
    }

    [Fact]
    public void A_body_identifier_is_not_reported_when_the_handler_reads_the_caller()
    {
        var app = Build(a => a.MapPut("/api/invoices", (UpdateInvoiceRequest request, ClaimsPrincipal user) =>
                                 Results.Ok(user.Identity?.Name))
                              .RequireAuthorization());

        Assert.Empty(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);
    }

    [Fact]
    public void A_route_identifier_still_takes_precedence_over_the_body()
    {
        // Both present: the route rules are the higher-confidence ones and must win, rather
        // than the endpoint being reported twice.
        var app = Build(a => a.MapPut("/api/invoices/{invoiceId}",
                                 (string invoiceId, UpdateInvoiceRequest request) => Results.Ok())
                              .RequireAuthorization());

        var finding = Assert.Single(AuthorizationSurfaceAnalyzer.Analyze(app).Findings);
        Assert.Equal(FindingCodes.UnscopedResourceAccess, finding.Code);
    }

    private sealed class OwnershipRequirement : IAuthorizationRequirement;

    // --- ignore patterns ----------------------------------------------------------------

    [Theory]
    [InlineData("health")]
    [InlineData("health/ready")]
    [InlineData("home_page_health_check")]
    [InlineData("api_health_check")]
    [InlineData("api/health-check")]
    [InlineData("HealthCheck")]
    public void Health_probe_routes_are_ignored(string route) =>
        Assert.Empty(AuthorizationSurfaceAnalyzer.Analyze([Anonymous(route)]).Findings);

    [Theory]
    [InlineData("api/patient-health-records/{id}")]
    [InlineData("api/health-plans/{planId}")]
    public void Routes_that_merely_contain_health_are_not_ignored(string route) =>
        Assert.NotEmpty(AuthorizationSurfaceAnalyzer.Analyze([Anonymous(route)]).Findings);

    private static HttpEndpointInfo Anonymous(string route) => new()
    {
        DisplayName = route,
        RoutePattern = route,
        HttpMethods = ["GET"]
    };
}

/// <summary>
/// A handler often delegates the ownership check to a helper it calls. One hop covers that;
/// a call through an injected interface still does not, and that is documented.
/// </summary>
public class CallGraphTests
{
    private static HandlerInspection Inspect(string name) =>
        HandlerPrincipalInspector.Inspect(
            typeof(CallGraphTests).GetMethod(name,
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static));

    private sealed class OwnershipHelper
    {
        public static string? OwnerOf(HttpContext ctx) => ctx.User.Identity?.Name;
    }

    private interface ITenantContext
    {
        string TenantId { get; }
    }

    private sealed class TenantContext(IHttpContextAccessor accessor) : ITenantContext
    {
        public string TenantId => accessor.HttpContext?.User.Identity?.Name ?? "";
    }

    private static string ViaHelper(string id, HttpContext ctx) => id + OwnershipHelper.OwnerOf(ctx);

    private static string ViaNothing(string id) => id;

    private static string ViaInterface(string id, ITenantContext tenant) => id + tenant.TenantId;

    private static async Task<string> ViaAsyncHelper(string id, HttpContext ctx)
    {
        await Task.Yield();
        return id + OwnershipHelper.OwnerOf(ctx);
    }

    [Fact]
    public void A_helper_that_reads_the_caller_makes_the_handler_aware()
    {
        // The handler's own IL never mentions the principal; the method it calls does.
        Assert.Equal(HandlerInspection.PrincipalAware, Inspect(nameof(ViaHelper)));
    }

    [Fact]
    public void The_hop_works_through_an_async_handler() =>
        Assert.Equal(HandlerInspection.PrincipalAware, Inspect(nameof(ViaAsyncHelper)));

    [Fact]
    public void A_handler_that_calls_nothing_relevant_is_still_blind() =>
        Assert.Equal(HandlerInspection.PrincipalBlind, Inspect(nameof(ViaNothing)));

    [Fact]
    public void A_call_through_an_injected_interface_remains_the_blind_spot()
    {
        // The interface method has no body, and choosing an implementation would mean knowing
        // the container's registrations. This is the limitation the README documents; the test
        // exists so a change in behaviour is a deliberate one.
        Assert.Equal(HandlerInspection.PrincipalBlind, Inspect(nameof(ViaInterface)));
        Assert.NotNull(typeof(TenantContext));
    }
}

/// <summary>
/// A Razor Page has one endpoint and several handler methods — OnGet, OnPost and friends.
/// The end-to-end wiring is proved by the eShopOnWeb run in docs/real-world.md; this covers
/// how several results are combined into one.
/// </summary>
public class MultipleHandlerTests
{
    private static string Blind(string id) => id;

    private static string Aware(string id, HttpContext ctx) => id + ctx.User.Identity?.Name;

    private static System.Reflection.MethodInfo Method(string name) =>
        typeof(MultipleHandlerTests).GetMethod(name,
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;

    [Fact]
    public void No_handlers_is_unknown() =>
        Assert.Equal(HandlerInspection.Unknown, HandlerPrincipalInspector.InspectAll([]));

    [Fact]
    public void All_blind_handlers_make_the_endpoint_blind() =>
        Assert.Equal(
            HandlerInspection.PrincipalBlind,
            HandlerPrincipalInspector.InspectAll([Method(nameof(Blind)), Method(nameof(Blind))]));

    [Fact]
    public void One_aware_handler_makes_the_endpoint_aware()
    {
        // The conservative reading is the one that avoids claiming a defect: if any handler
        // on the endpoint can see the caller, the endpoint is not provably blind.
        Assert.Equal(
            HandlerInspection.PrincipalAware,
            HandlerPrincipalInspector.InspectAll([Method(nameof(Blind)), Method(nameof(Aware))]));
    }
}

/// <summary>
/// A handler body that only throws is a placeholder, not an implementation. ASP.NET Core
/// Identity is built this way — the routed page model's handlers throw, and the generic
/// subclass registered at runtime holds the code that reads the principal — so treating a
/// stub as proof of blindness reports a safe endpoint as a defect.
/// </summary>
public class StubHandlerTests
{
    private abstract class PageBase
    {
        public virtual string Handle(string id) => throw new NotImplementedException();

        public virtual string HandleWithMessage(string id) =>
            throw new NotSupportedException("overridden in the derived type");
    }

    private sealed class RealPage : PageBase
    {
        public override string Handle(string id) => id;
    }

    private static HandlerInspection InspectOn<T>(string name) =>
        HandlerPrincipalInspector.Inspect(
            typeof(T).GetMethod(name,
                System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance));

    [Fact]
    public void A_handler_that_only_throws_is_unknown_not_blind() =>
        Assert.Equal(HandlerInspection.Unknown, InspectOn<PageBase>(nameof(PageBase.Handle)));

    [Fact]
    public void A_stub_that_throws_with_an_argument_is_also_unknown() =>
        Assert.Equal(HandlerInspection.Unknown, InspectOn<PageBase>(nameof(PageBase.HandleWithMessage)));

    [Fact]
    public void A_real_handler_that_returns_is_still_judged() =>
        Assert.Equal(HandlerInspection.PrincipalBlind, InspectOn<RealPage>(nameof(RealPage.Handle)));

    [Fact]
    public void A_handler_that_throws_on_one_path_but_returns_on_another_is_still_judged()
    {
        // Guard clauses are ordinary code, not a stub: the body can still return.
        Assert.Equal(HandlerInspection.PrincipalBlind, InspectOn<GuardedPage>(nameof(GuardedPage.Handle)));
    }

    private sealed class GuardedPage
    {
        public string Handle(string id) =>
            id.Length == 0 ? throw new ArgumentException(null, nameof(id)) : id;
    }
}
