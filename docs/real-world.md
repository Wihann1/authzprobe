# Running AuthzProbe against a real application

The [corpus check](../tools/corpus/run-corpus.sh) in CI probes the stock ASP.NET Core
templates on every push. Templates are small by design — one to four endpoints — so they prove
the rules do not misfire, not that they find anything.

This is the other half: a run against a real, substantial application that nobody wrote for
this tool.

## The applications

Five, chosen to be as unlike each other as possible, cloned from public GitHub repositories and
probed without modifying a line of their source.

| Application | Shape | Endpoints | Findings |
|---|---|---|---|
| [eShopOnWeb](https://github.com/dotnet-architecture/eShopOnWeb) `PublicApi` | Minimal APIs via a third-party endpoint library, JWT | 8 | 8 |
| [eShopOnWeb](https://github.com/dotnet-architecture/eShopOnWeb) `Web` | MVC + Razor Pages + Blazor + Identity | 68 | 15 |
| [Jellyfin](https://github.com/jellyfin/jellyfin) | Media server, controller-heavy, custom auth policies | 420 | 65 |
| [Clean Architecture](https://github.com/ardalis/CleanArchitecture) | FastEndpoints (REPR), Aspire | 11 | 6 |
| [nopCommerce](https://github.com/nopSolutions/nopCommerce) | Plugin commerce, authorization by custom MVC filters | 1675 | **1** |

[OrchardCore](https://github.com/OrchardCMS/OrchardCore) was attempted and dropped: its main
branch needs SDK 10.0.302 and this machine has 10.0.111. That is an environment limit, not a
result.

Two of these runs changed the tool.

### nopCommerce: 1,675 findings that were all true and all useless

nopCommerce never calls `AddAuthorization`. It has no policies and no `[Authorize]` outside one
base controller; access is enforced by its own MVC filters and an `IPermissionService`. So every
one of its 1,675 endpoints genuinely carries no authorization metadata, and a literal reading
produced 1,675 findings — the same failure as reporting a stylesheet per file, in a different
costume.

A report that flags everything says nothing. When practically the whole surface has no
authorization metadata, the likeliest explanation is not that everything is unprotected but that
enforcement lives somewhere AuthzProbe cannot see. That is now said once, as **AZP007**, and it
says the report is inconclusive rather than clean. nopCommerce went from 1,675 findings to 1.

### Identity UI: a stub that looked like a defect

The `Web` run reported `/Identity/Account/Manage/ExternalLogins` as AZP002 — unable to scope to
the caller. It was wrong. ASP.NET Core Identity routes to a non-generic page model whose handlers
only `throw`, while the real implementation lives in a generic subclass registered at runtime,
and that one reads `User` correctly.

A body that only throws is a placeholder, not an implementation, and proves nothing either way.
Such handlers are now `Unknown` rather than `PrincipalBlind`, which is the same discipline the
IL walker already applied to an incomplete decode.

## The application in detail

[dotnet-architecture/eShopOnWeb](https://github.com/dotnet-architecture/eShopOnWeb) at commit
`4da8212`, Microsoft's ASP.NET Core reference application. It has the shapes a toy does not:
JWT bearer authentication, ASP.NET Identity, EF Core, MVC controllers, Razor Pages, a Blazor
WASM admin client, minimal-API endpoints registered by a third-party library
(`MinimalApi.Endpoint`), `[Authorize]` applied as a lambda parameter attribute, and
authorization applied by page convention rather than by attribute.

AuthzProbe was installed the way a user installs it — `dotnet add package AuthzProbe` — and
attached with the hosting startup. **No source file of eShopOnWeb was modified.**

```bash
UseOnlyInMemoryDatabase=true \
ASPNETCORE_ENVIRONMENT=Development \
ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=AuthzProbe \
AUTHZPROBE_EXIT=1 \
dotnet run --project src/Web
```

## Results

| Project | Endpoints analysed | Findings |
|---|---|---|
| `src/PublicApi` | 8 | 6 — five AZP001, one AZP004 |
| `src/Web` | 70 | 12 — eleven AZP001, one AZP005 |

Twelve findings across seventy endpoints. Every one was checked against the source by hand.

## The finding that matters

AuthzProbe reported `/Admin` and `/Admin/Index` as **AZP001 — reachable without
authentication**, on an application whose `Pages/Admin/Index.cshtml.cs` reads:

```csharp
[Authorize(Roles = BlazorShared.Authorization.Constants.Roles.ADMINISTRATORS)]
public class IndexModel : PageModel
```

The attribute is right there. The page is not protected by it. `Pages/Admin/Index.cshtml`
declares `@page` but has no `@model IndexModel` directive, so the page never binds to that
PageModel and the attribute never reaches the endpoint. The runtime metadata confirms it —
`/Admin/Index` carries **zero** `IAuthorizeData`, while `/Admin/EditCatalogItem`, whose
`.cshtml` does declare `@model`, carries one.

Verified against the running application:

```
GET /Admin                    ->  HTTP 200          (anonymous, flagged)
GET /Admin/EditCatalogItem    ->  HTTP 302 -> login (control: has @model)
GET /Basket/Checkout          ->  HTTP 302 -> login (control: AuthorizePage convention)
```

The two controls are as important as the finding: AuthzProbe stayed silent on both pages that
really are protected, including the one protected by a convention rather than an attribute.

**This is the case for reading a routing table instead of source.** Anything that reads source
and pairs a PageModel to its page by naming convention concludes `/Admin` is
administrators-only, because the attribute is present and the names match. It is only false at
runtime. A tool that reads what the framework actually built sees the truth; a tool that reads
what the developer wrote sees the intention.

Severity here is modest — the page is the Blazor admin shell, and the API endpoints behind it
do enforce the administrator role — so this is information disclosure rather than privilege
escalation. The defect *class* is what matters: an authorization attribute that silently does
nothing, in a reference application many teams have copied from.

## What it missed

`PUT /api/catalog-items` and `POST /api/catalog-items` are administrator-guarded endpoints that
address a specific catalog item by an identifier in the **request body**, not the route.
AuthzProbe raised nothing on them, because `ExposesResourceIdentifier` only examines route
parameters. That is the documented limitation in the README's *What it does not do*, and this
is what it looks like on real code.

## What the spread showed

- **Every routing style was seen**: minimal APIs, MVC controllers, Razor Pages, and FastEndpoints'
  REPR endpoints all reached the scanner with their handlers attached.
- **Precision held on the two apps that use ASP.NET Core authorization properly.** Jellyfin's
  64 AZP001s are real — `BrandingController` and the streaming controllers carry neither
  `[Authorize]` nor `[AllowAnonymous]`. Clean Architecture's three AZP003s are real: its
  `Contributors` CRUD calls `AllowAnonymous()` on `{ContributorId:int}` routes.
- **The failure mode to watch is an application whose authorization AuthzProbe cannot observe.**
  That is now detected and stated rather than drowned in findings.

## Why this is not in CI

Pinning eShopOnWeb into the build would mean cloning a large repository, standing up its
database and tracking its upstream changes, and the check would fail for reasons that have
nothing to do with this tool. The templates give a stable, fast regression guard; a run like
this one is worth repeating by hand when the rules change.
