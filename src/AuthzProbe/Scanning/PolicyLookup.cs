using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace AuthzProbe.Scanning;

/// <summary>
/// Resolves the authorization policy an endpoint would actually be evaluated against.
/// </summary>
/// <remarks>
/// Endpoint metadata records what was <em>declared</em>, not what the runtime will
/// <em>enforce</em>. Two things live outside the metadata entirely: a named policy is
/// just a string until someone looks it up, and a fallback policy protects endpoints
/// that carry no metadata at all. Reading metadata alone therefore both over-reports
/// (every endpoint in a deny-by-default application looks unprotected) and under-reports
/// (a policy named "InvoiceOwner" that only calls RequireAuthenticatedUser looks like
/// ownership enforcement). This resolves both against the application's real
/// <see cref="IAuthorizationPolicyProvider"/>.
/// </remarks>
internal sealed class PolicyLookup
{
    private readonly IAuthorizationPolicyProvider? _provider;

    private PolicyLookup(IAuthorizationPolicyProvider? provider, AuthorizationPolicy? fallbackPolicy)
    {
        _provider = provider;
        FallbackPolicy = fallbackPolicy;
    }

    /// <summary>Used when no service provider is available, so nothing can be resolved.</summary>
    public static PolicyLookup None { get; } = new(null, null);

    /// <summary>
    /// The policy applied to endpoints carrying no authorization metadata, or null when the
    /// application has not configured one.
    /// </summary>
    public AuthorizationPolicy? FallbackPolicy { get; }

    /// <summary>True when named policies can be resolved to their requirements.</summary>
    public bool CanResolve => _provider is not null;

    /// <summary>Builds a lookup from an application's services, tolerating an absent provider.</summary>
    public static PolicyLookup From(IServiceProvider? services)
    {
        if (services is null)
        {
            return None;
        }

        IAuthorizationPolicyProvider? provider;
        try
        {
            provider = services.GetService<IAuthorizationPolicyProvider>();
        }
        catch (Exception)
        {
            // A disposed or partially built container must not take the scan down with it.
            return None;
        }

        if (provider is null)
        {
            return None;
        }

        AuthorizationPolicy? fallback;
        try
        {
            fallback = provider.GetFallbackPolicyAsync().GetAwaiter().GetResult();
        }
        catch (Exception)
        {
            fallback = null;
        }

        return new PolicyLookup(provider, fallback);
    }

    /// <summary>
    /// Computes the policy the authorization middleware would build for this endpoint, using
    /// the framework's own combination rules so named policies, roles, schemes and the default
    /// policy are folded in exactly as they are at request time.
    /// </summary>
    /// <returns>
    /// The effective policy, and whether it could be resolved at all. A false there means a
    /// named policy could not be found, so nothing may be concluded about this endpoint.
    /// </returns>
    public (AuthorizationPolicy? Policy, bool Resolved) Combine(
        IReadOnlyList<IAuthorizeData> authorizeData,
        IReadOnlyList<AuthorizationPolicy> attachedPolicies)
    {
        if (_provider is null)
        {
            // Without a provider an inline policy is still readable, but a named one is
            // opaque — and an opaque policy cannot support any conclusion.
            var inline = attachedPolicies.Count > 0
                ? AuthorizationPolicy.Combine(attachedPolicies)
                : null;

            var namesUnresolved = authorizeData.Any(a => !string.IsNullOrWhiteSpace(a.Policy));

            return (inline, !namesUnresolved);
        }

        try
        {
            var combined = AuthorizationPolicy
                .CombineAsync(_provider, authorizeData, attachedPolicies)
                .GetAwaiter()
                .GetResult();

            return (combined, true);
        }
        catch (Exception)
        {
            // A policy name with no registration throws. The application is misconfigured
            // or uses a provider we cannot drive; either way, report nothing rather than
            // guess.
            return (null, false);
        }
    }
}
