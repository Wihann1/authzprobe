# Running AuthzProbe against real applications

> **Correction, and how to read this page.** An earlier version of this document reported these
> runs as a success. An independent review — a fresh session given the package and the same five
> applications, with no access to these results — falsified the central claim. The findings below
> are the corrected ones. What the page used to say, and why it was wrong, is recorded at the
> bottom rather than deleted.

## The applications

Five, chosen to be as unlike each other as possible, cloned from public GitHub repositories and
probed without modifying a line of their source.

| Application | Shape | Endpoints |
|---|---|---|
| [eShopOnWeb](https://github.com/dotnet-architecture/eShopOnWeb) `PublicApi` | Minimal APIs via a third-party endpoint library, JWT | 8 |
| [eShopOnWeb](https://github.com/dotnet-architecture/eShopOnWeb) `Web` | MVC + Razor Pages + Blazor + Identity | 68 |
| [Jellyfin](https://github.com/jellyfin/jellyfin) | Media server, controller-heavy, custom policies | 420 |
| [Clean Architecture](https://github.com/ardalis/CleanArchitecture) | FastEndpoints (REPR), Aspire | 11 |
| [nopCommerce](https://github.com/nopSolutions/nopCommerce) | Plugin commerce, authorization by custom MVC filters | 1675 |

[OrchardCore](https://github.com/OrchardCMS/OrchardCore) was attempted and dropped: its main
branch needs a newer SDK than the machine had. That is an environment limit, not a result.

Across roughly 2,177 endpoints the independent review classified the findings as **7 true and
actionable, 77 "a public thing is public", and 9 false positives.**

## What holds up

**AZP001 has no false positives.** Every endpoint it called reachable without authentication was
reachable without authentication. The reviewer tested this hard: on Jellyfin, flagged endpoints
returned 200 anonymously while unflagged controls returned 401, and media routes were probed with
a random GUID so that 404 (handler reached) separated cleanly from 401 (gate present).

**The `/Admin` find is real and is the best thing here.** eShopOnWeb's `Pages/Admin/Index.cshtml.cs`
carries `[Authorize(Roles = ADMINISTRATORS)]`, but `Index.cshtml` has no `@model` directive, so the
page never binds to that model and the attribute is inert. Verified: `GET /Admin` returns 200
anonymously while two controls redirect to login. Source analysis would call that page protected.

**AZP007 works.** nopCommerce enforces access through its own MVC filters and never calls
`AddAuthorization`, so a literal reading produced 1,675 findings on 1,675 endpoints. Collapsing
that to one finding, framed as *inconclusive rather than clean*, was judged good engineering.

## What does not hold up

**AZP002 — the rule this package exists for — did not fire once across 2,177 endpoints.** It has
no demonstrated true positive on real code.

**It rated a real IDOR as Info.** eShopOnWeb's `GET /order/detail/{orderId}` is genuinely
vulnerable: the controller passes `User.Identity.Name` into a MediatR query, and
`GetOrderDetailsHandler` builds `new OrderWithItemsByIdSpec(request.OrderId)` and never reads the
user name. The reviewer registered an unprivileged account and pulled another user's order and
shipping address. AuthzProbe reported it as **AZP005 (Info)**, below the default fail threshold,
on a list the documentation described as "a review list, not a defect list".

It was demoted *because the handler touches `User`*. That is the flaw, stated plainly: **reading
the principal and then discarding it is exactly what this bug looks like from the outside**, so the
principal-awareness test is defeated most reliably by the defect it hunts. The same reasoning
error was made by hand during the original analysis, which cleared this endpoint after reading the
call site rather than the handler.

**Object-level analysis can be disabled silently.** If an application puts a custom requirement in
its `DefaultPolicy`, every bare `[Authorize]` endpoint resolves to a policy carrying a substantive
requirement, so the object-level rules skip all of them. On Jellyfin that was 0 of ~355 endpoints
analysed, and the report said nothing about it. Among what went unexamined was
`GET /Users/{userId}`, where a non-admin can read any user's full record.

**Ownership through an injected interface still reads as a defect.** nopCommerce's `IWorkContext`
is the ordinary service-layer idiom, and endpoints using it are reported as AZP002.

## Verdict

Worth running on eShopOnWeb `Web` and Clean Architecture. Marginal on `PublicApi`. Partly on
Jellyfin, and only if you know to distrust its silence. Not on nopCommerce — which the tool
says itself.

The honest description of what has verified true positives behind it is **"what this application
declares is not what it enforces"**, not "finds IDOR".

## What this page said before, and why it was wrong

The previous version reported the same runs as a clean success: eShopOnWeb `Web` a precision win,
Jellyfin evidence that the rules hold on a large surface, and a "What it missed" section listing a
single limitation that had already been fixed.

Three things were wrong with it.

1. **It analysed the app containing the IDOR and never mentioned it.** The endpoint was examined
   by hand and cleared, on the strength of the controller passing the user name into the query. The
   handler that discards it was not read. A claim was made from the call site instead of the
   implementation.
2. **It called Jellyfin a precision success while the core rule was switched off there.** The
   run produced no AZP002 findings, and that absence was read as a clean result rather than as a
   question about why the rule never fired.
3. **Its "What it missed" section described a closed gap and none of the live ones**, which made
   the limitations look smaller than they are.

The independent review that found all of this was given the package and the five applications with
no context, and was told explicitly not to read this file until it had reached its own conclusions.
That is the review worth repeating whenever these rules change.
