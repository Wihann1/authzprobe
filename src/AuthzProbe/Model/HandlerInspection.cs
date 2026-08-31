namespace AuthzProbe.Model;

/// <summary>
/// What inspecting the handler's own code tells us about whether it can scope
/// a result to the calling user.
/// </summary>
public enum HandlerInspection
{
    /// <summary>The handler could not be inspected, so nothing is known either way.</summary>
    Unknown,

    /// <summary>
    /// The handler references the authenticated principal, so it may well be enforcing
    /// ownership in its body. Needs a human to confirm the check is the right one.
    /// </summary>
    PrincipalAware,

    /// <summary>
    /// Neither the handler nor the methods it calls directly reference the authenticated
    /// principal. That is evidence it is not filtering by the caller, not proof: a service
    /// injected as an interface can reach the principal without the handler naming it.
    /// </summary>
    PrincipalBlind
}
