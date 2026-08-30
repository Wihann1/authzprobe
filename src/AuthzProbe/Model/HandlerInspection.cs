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
    /// The handler never references the authenticated principal. It cannot know who is
    /// calling, so it cannot be filtering by them.
    /// </summary>
    PrincipalBlind
}
