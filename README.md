# AuthzProbe

[![CI](https://github.com/Wihann1/authzprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/Wihann1/authzprobe/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/AuthzProbe.svg)](https://www.nuget.org/packages/AuthzProbe)
[![Downloads](https://img.shields.io/nuget/dt/AuthzProbe.svg)](https://www.nuget.org/packages/AuthzProbe)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Finds the ASP.NET Core endpoints where nothing answers the question "is this row yours?"**

```
dotnet add package AuthzProbe
```

Static analysis can prove your query is parameterised. It cannot know that `GET /invoices/{id}`
should only return invoices belonging to the caller, because ownership is a property of your
domain, not of your syntax. That gap is where broken object level authorization lives — OWASP
API #1, and the defect class that compiles cleanly and passes every test you have.

AuthzProbe reads the routing table your application actually built and reports the endpoints where
that question is *unanswered* — no resource-based policy, and no reference to the caller in the
handler. It reports where a check is **missing or invisible**. It does not prove a vulnerability,
and a clean report is not a security assurance. See [what it does not do](#what-it-does-not-do).

## Use it

**As a test**, so it runs on every pull request. This is the usage to reach for first — a
heuristic should not be able to stop your application from booting:

```csharp
[Fact]
public void Authorization_surface_is_clean()
{
    var app = BuildApp();
    AuthorizationSurfaceAnalyzer.Analyze(app).ThrowIfFailed();
}
```

**Against an application you have not modified.** Add the package, name it as a hosting startup
assembly, and the probe attaches to the running application and reports on the routing table the
framework actually built:

```bash
ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=AuthzProbe \
AUTHZPROBE_EXIT=1 \
dotnet run --project ./YourApi
```

It writes the report to stdout, exits non-zero when the surface fails, and takes
`AUTHZPROBE_REPORT_PATH` to write the markdown to a file. A hosting startup assembly is loaded
only when it is named in that variable, so referencing the package never attaches the probe to
your production application by accident.

**At startup**, if you want the check inside the application itself:

```csharp
var app = builder.Build();
app.MapControllers();

var report = AuthorizationSurfaceAnalyzer.Analyze(app);
report.ThrowIfFailed();
```

## What it finds

| Code | Severity | What it means |
|---|---|---|
| **AZP001** | Error | Endpoint has no authorization metadata and no `[AllowAnonymous]` — it is anonymous *by omission*, not by decision. |
| **AZP002** | Warning | Endpoint takes an object identifier, the authorization it *enforces* stops at "signed in", and **neither the handler nor the methods it calls reference the caller**. The strongest signal here — still a finding to check, not a proven bug. |
| **AZP003** | Warning | Explicitly anonymous *and* addresses a specific object. Guessable ids are readable by anyone. |
| **AZP004** | Info | Object-addressing endpoint guarded only by a role. A role says what kind of user you are, never which rows are yours. |
| **AZP005** | Info | Object-addressing endpoint with no declarative scoping, but its handler *does* touch the caller — or could not be inspected. A review list, not a defect list. |
| **AZP006** | Info | The route shows no identifier, but the handler binds one from the **request body**, and nothing scopes it to the caller. The same defect, hidden from the route table. |
| **AZP007** | Error | *Nothing* on the surface carries authorization metadata. Usually means the application enforces access somewhere this tool cannot see, so the report is inconclusive rather than clean. |

### It reads what is enforced, not what is declared

Endpoint metadata records what was *declared*. Three things decide what the authorization
middleware actually *enforces*, and none of them are visible to a literal read of that metadata:

- **The fallback policy.** `options.FallbackPolicy` protects every endpoint that declares nothing.
  A scanner that misses it reports the whole of a deny-by-default application as anonymous — that
  is, it fails the build of exactly the applications that took the advice AZP001 gives.
- **Named policies.** `RequireAuthorization("InvoiceOwner")` is a string until someone resolves it.
  A policy named like an ownership rule whose body is `RequireAuthenticatedUser()` enforces nothing
  of the kind, and AuthzProbe reports it as **AZP002** on the strength of its requirements, not its
  name.
- **Inline policies.** `RequireAuthorization(p => p.RequireRole("Admin"))` compiles the role into an
  `AuthorizationPolicy` where it never appears on `IAuthorizeData`.

AuthzProbe resolves all three through the application's own `IAuthorizationPolicyProvider`, using the
framework's own combination rules — so what it judges is the policy the middleware would build. When
a named policy cannot be resolved, the endpoint raises nothing rather than a guess.

### Controllers and minimal APIs both

Minimal APIs put the handler's `MethodInfo` into endpoint metadata. Controllers do not — they carry a
`ControllerActionDescriptor` instead. Reading only the former leaves every MVC action uninspectable,
quietly demoting the whole of a controller-based codebase to the review list. Both are read.

Static assets are not an authorization surface. `MapStaticAssets()` registers one endpoint per file —
several hundred in a stock MVC or Blazor application — and they are excluded, along with routing
fallbacks. Set `IncludeInfrastructureEndpoints` to analyse them anyway.

## Sample output

```
# AuthzProbe report

- Endpoints analysed: **12**
- Findings: **9** (1 error, 5 warning, 3 info)
- Result: **FAIL**

## AZP002 — Object-addressing endpoint shows no sign of scoping to the caller (4)

- `GET /api/invoices/{id:guid}`
- `GET /api/tenants/{tenantId}/documents/{documentId}`
- `GET /api/legacy-invoices/{invoiceId}`
- `GET /api/orders/{orderId}`

**Fix:** Enforce ownership server-side: derive the owner from the authenticated principal
rather than the request, or apply a resource-based policy via IAuthorizationService.
```

## Adopting it on an existing codebase

A tool that reports two hundred findings on the day it is installed gets uninstalled. Record
what the codebase already has, and fail only on what is added to it:

```bash
# once
AUTHZPROBE_WRITE_BASELINE=authzprobe-baseline.txt \
ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=AuthzProbe dotnet run --project ./YourApi

# thereafter, in CI
AUTHZPROBE_BASELINE=authzprobe-baseline.txt AUTHZPROBE_EXIT=1 \
ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=AuthzProbe dotnet run --project ./YourApi
```

The file is one finding per line, sorted, so it diffs cleanly — a pull request that adds a line
is visibly adding an authorization gap. Findings that disappear are reported as stale entries
to delete, so the baseline cannot go on forgiving a defect that has come back. In code it is
`options.Baseline = AuthzProbeBaseline.Load(path)`.

## Configuration

```csharp
var options = new AuthzProbeOptions
{
    // Once the existing surface is clean, stop new IDOR-shaped endpoints landing.
    TreatUnscopedResourceAccessAsError = true
};

options.IgnoredRoutePatterns.Add("internal/*");
options.SuppressedCodes.Add(FindingCodes.RoleOnlyResourceAccess);

AuthorizationSurfaceAnalyzer.Analyze(app, options).ThrowIfFailed();
```

`health*`, `swagger*`, `openapi*`, `.well-known/*`, `_framework/*` and `error*` are ignored by default.

## How AZP002 avoids drowning you in false positives

The common, correct way to scope a result in ASP.NET Core is inside the handler:

```csharp
var invoice = await _repo.GetForUserAsync(id, User.GetUserId());
```

Routing metadata cannot see that, so a naive check would flag every `{id}` endpoint in your
codebase. AuthzProbe closes the gap from the other side: it reads the handler's IL — unwrapping
async state machines to find the real body — and asks whether the code references the
authenticated principal at all.

A handler that never touches `User`, `ClaimsPrincipal`, `HttpContext` or `IAuthorizationService`,
and calls nothing that does, is unlikely to be filtering by the caller. Those endpoints are
reported as **AZP002**. This is the strongest signal the tool has, and it is still evidence rather
than proof — a service injected as an interface can reach the principal without the handler ever
naming it, and AuthzProbe will not see that.

Everything else — handlers that do reference the caller, and handlers that could not be read —
goes to **AZP005** for review.

## Why a runtime library and not an analyzer

A Roslyn analyzer sees source. What decides whether an endpoint is protected is not in the
source of the endpoint: `MapControllers` applies conventions, `AddAuthorization` registers
policies under names that are resolved later, `FallbackPolicy` protects endpoints that declare
nothing, and `RequireAuthorization(configure)` compiles rules into an object no attribute ever
mentions. Those decisions are spread across files an analyzer would have to stitch together, and
some of them are only knowable once the container is built.

Reading the routing table the framework actually constructed sidesteps all of it: what is
scanned is what will be served. The cost is that the application has to start, which is why the
hosting startup exists — so the thing being measured is a real application, unmodified.

## Tested against applications nobody wrote for it

Unit tests prove the rules behave on endpoints written to exercise them, which is a low bar for
a tool whose whole job is judging other people's code. So CI also generates the stock ASP.NET
Core templates — `webapi`, `webapi --use-controllers`, `mvc`, `webapp` — on both supported
frameworks, and probes each one without modifying a line of its source:

```bash
tools/corpus/run-corpus.sh --framework net8.0
tools/corpus/run-corpus.sh --framework net10.0
```

The templates consume AuthzProbe as a package from a local feed, not as a project reference, so
packaging mistakes surface here too.

The expectations live in [`tools/corpus/expectations.tsv`](tools/corpus/expectations.tsv), and
the cap on analysed endpoints is the guard that matters. `MapStaticAssets` registers one endpoint
per file, and an earlier version of this tool reported **385 findings on a stock MVC application,
380 of them about `bootstrap.css`**. Unit tests were all green at the time. The corpus is what
catches that class of mistake.

Templates are small by design, so they show the rules do not misfire rather than that they find
anything. [**docs/real-world.md**](docs/real-world.md) is the other half: a run against
Microsoft's eShopOnWeb reference application — 78 endpoints across two projects, installed as a
package and attached without modifying a line of its source.

Five applications were probed — eShopOnWeb, Jellyfin, Clean Architecture, nopCommerce — covering
minimal APIs, MVC, Razor Pages and FastEndpoints. It found `/Admin` served anonymously despite `[Authorize(Roles = ADMINISTRATORS)]` sitting on the
page's model class. The `.cshtml` has no `@model` directive, so the page never binds to that
model and the attribute never reaches the endpoint — confirmed with `GET /Admin` returning 200
while two genuinely protected pages returned 302 to the login page. An analyzer reading source
concludes that page is administrators-only, because the attribute is present and the names match.
It is only false at runtime.

## What it does not do

**A clean report is not a security assurance.** It means AuthzProbe found nothing it knows how to
look for. Read it as a list of questions to answer, never as evidence that an application is safe,
and never as a substitute for review or testing.

It reports where an ownership check is *missing or invisible to it*, not whether a check that
exists is *correct*. An endpoint with a resource-based policy passes; proving that policy right is
your tests' job.

Findings are **not proven vulnerabilities**. Each one says what was observed. Confirm before
acting, and expect false positives in the cases below.

The known blind spots:

- Calls the handler makes are followed one level deep, so a helper that reads the principal counts.
  A call through an **injected interface** is not followed: the interface method has no body, and
  choosing an implementation would mean knowing the container's registrations. A service reached
  that way is still reported as AZP002.
- An identifier in the query string is treated exactly like one in the route. One bound from the
  request body is reported as **AZP006** at Info, because body binding is inferred from the
  handler's signature rather than declared in a route template.
- A handler that merely reads the principal — logging `User.Identity.Name`, say — counts as
  principal-aware and drops from AZP002 to AZP005. The check is a capability test, not a proof that
  the value is used for filtering.

## Try it

From the repository root:

```bash
cd authzprobe
dotnet run --project samples/SampleApi -f net10.0 -- --probe-only
```

The sample maps thirteen endpoints across minimal APIs and controllers. Nine raise a finding —
including a policy named `MustOwnTheRecord` that enforces nothing beyond authentication — and the
probe exits non-zero.

Run the tests the same way:

```bash
dotnet test
```

And probe the stock ASP.NET Core templates, which is what CI does:

```bash
tools/corpus/run-corpus.sh --framework net10.0
```

## Targets

`net8.0` and `net10.0` — the .NET releases still in support — with the test suite running against
both. MIT licensed.
