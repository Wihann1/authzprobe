using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using SampleApi.Authorization;

namespace SampleApi;

/// <summary>
/// A deliberately mixed API surface: some endpoints are correctly secured, some carry
/// exactly the defects AuthzProbe exists to find. Used by the sample app and the tests,
/// so both exercise the same surface.
/// </summary>
public static class VulnerableEndpoints
{
    /// <summary>Registers the authentication, policies and controllers the sample surface needs.</summary>
    public static IServiceCollection AddVulnerableApi(this IServiceCollection services)
    {
        services.AddAuthentication();
        services.AddAuthorization(options =>
        {
            // A real resource-based policy: it carries a requirement that asks a question
            // about the object.
            options.AddPolicy("InvoiceOwner", policy => policy.Requirements.Add(new InvoiceOwnerRequirement()));

            // A policy in name only. It reads like a scoping rule and enforces nothing
            // beyond "signed in" — the shape AuthzProbe used to be fooled by.
            options.AddPolicy("MustOwnTheRecord", policy => policy.RequireAuthenticatedUser());
        });

        services.AddSingleton<IAuthorizationHandler, InvoiceOwnerHandler>();

        // The controllers live in this assembly rather than the entry assembly, so the
        // application part has to be named explicitly for the test host to find them.
        services.AddControllers()
            .AddApplicationPart(typeof(VulnerableEndpoints).Assembly);

        return services;
    }

    /// <summary>Maps the sample surface onto the given route builder.</summary>
    public static void MapVulnerableEndpoints(this IEndpointRouteBuilder app)
    {
        // --- legitimately public, and ignored by default configuration -------------------
        app.MapGet("/health", () => Results.Ok("healthy"));

        // --- AZP001: nobody opted this in. Anonymous by omission. --------------------------
        app.MapGet("/api/reports/export", () => Results.Ok("every report, for anyone"));

        // --- AZP002: the IDOR shape. Authenticated, but nothing ties caller to invoice. ----
        app.MapGet("/api/invoices/{id:guid}", (Guid id) => Results.Ok(new { id }))
           .RequireAuthorization();

        // --- AZP002 again, via a tenant-scoped route that still checks nothing -------------
        app.MapGet("/api/tenants/{tenantId}/documents/{documentId}",
                (string tenantId, string documentId) => Results.Ok(new { tenantId, documentId }))
           .RequireAuthorization();

        // --- AZP002 again, behind a policy whose name promises more than it enforces -------
        app.MapGet("/api/legacy-invoices/{invoiceId}", (string invoiceId) => Results.Ok(new { invoiceId }))
           .RequireAuthorization("MustOwnTheRecord");

        // --- AZP003: explicitly public *and* addressing a specific object ------------------
        app.MapGet("/api/payslips/{payslipId}", (string payslipId) => Results.Ok(new { payslipId }))
           .AllowAnonymous();

        // --- AZP004: a role says what you are, never which rows are yours ------------------
        app.MapGet("/api/admin/users/{userId}", (string userId) => Results.Ok(new { userId }))
           .RequireAuthorization(policy => policy.RequireRole("Admin"));

        // --- clean: authenticated, and takes no object identifier -------------------------
        app.MapGet("/api/me", () => Results.Ok("the caller"))
           .RequireAuthorization();

        // --- clean: a resource-based policy is doing the ownership check -------------------
        app.MapGet("/api/secure-invoices/{id:guid}", (Guid id) => Results.Ok(new { id }))
           .RequireAuthorization("InvoiceOwner");

        // --- AZP005: no declarative scoping, but the handler does read the caller ---------
        app.MapGet("/api/statements/{statementId}", (string statementId, HttpContext ctx) =>
                Results.Ok(new { statementId, owner = ctx.User.Identity?.Name }))
           .RequireAuthorization();

        // --- clean: pagination parameters are not object identifiers ----------------------
        app.MapGet("/api/invoices", (int page, int pageSize) => Results.Ok(new { page, pageSize }))
           .RequireAuthorization();

        // --- controller-based endpoints: AZP002 on orders, AZP005 on receipts --------------
        app.MapControllers();
    }
}
