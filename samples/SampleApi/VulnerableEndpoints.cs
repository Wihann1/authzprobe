using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace SampleApi;

/// <summary>
/// A deliberately mixed API surface: some endpoints are correctly secured, some carry
/// exactly the defects AuthzProbe exists to find. Used by the sample app and the tests.
/// </summary>
public static class VulnerableEndpoints
{
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
    }
}
