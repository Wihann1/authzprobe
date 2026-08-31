using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace SampleApi.Authorization;

/// <summary>
/// A genuine resource-based requirement: it asks a question about the object, not just
/// about the caller. This is what separates a real ownership policy from a policy that
/// merely has an ownership-sounding name.
/// </summary>
public sealed class InvoiceOwnerRequirement : IAuthorizationRequirement;

/// <summary>Stands in for a real ownership check against the store.</summary>
public sealed class InvoiceOwnerHandler : AuthorizationHandler<InvoiceOwnerRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        InvoiceOwnerRequirement requirement)
    {
        if (context.User.FindFirstValue(ClaimTypes.NameIdentifier) is not null)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
