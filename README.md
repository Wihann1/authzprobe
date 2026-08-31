# AuthzProbe

[![CI](https://github.com/Wihann1/authzprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/Wihann1/authzprobe/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/AuthzProbe.svg)](https://www.nuget.org/packages/AuthzProbe)
[![Downloads](https://img.shields.io/nuget/dt/AuthzProbe.svg)](https://www.nuget.org/packages/AuthzProbe)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Fails your build when an ASP.NET Core endpoint can be pointed at somebody else's data.**

```
dotnet add package AuthzProbe
```

Static analysis can prove your query is parameterised. It cannot know that `GET /invoices/{id}`
should only return invoices belonging to the caller, because ownership is a property of your
domain, not of your syntax. That gap is where broken object level authorization lives — OWASP
API #1, and the defect class that compiles cleanly and passes every test you have.

AuthzProbe reads your routing table at startup and finds every endpoint where the ownership
question is *unanswered*, which is overwhelmingly where the answer turns out to be "it doesn't check".

## Use it

```csharp
var app = builder.Build();
app.MapControllers();

var report = AuthorizationSurfaceAnalyzer.Analyze(app);
report.ThrowIfFailed();
```

Or as a test, so it runs on every pull request:

```csharp
[Fact]
public void Authorization_surface_is_clean()
{
    var app = BuildApp();
    AuthorizationSurfaceAnalyzer.Analyze(app).ThrowIfFailed();
}
```

## What it finds

| Code | Severity | What it means |
|---|---|---|
| **AZP001** | Error | Endpoint has no authorization metadata and no `[AllowAnonymous]` — it is anonymous *by omission*, not by decision. |
| **AZP002** | Warning | Endpoint takes an object identifier, the authorization it *enforces* stops at "signed in", **and its handler never references the caller** — so it cannot be filtering by them. |
| **AZP003** | Warning | Explicitly anonymous *and* addresses a specific object. Guessable ids are readable by anyone. |
| **AZP004** | Info | Object-addressing endpoint guarded only by a role. A role says what kind of user you are, never which rows are yours. |
| **AZP005** | Info | Object-addressing endpoint with no declarative scoping, but its handler *does* touch the caller — or could not be inspected. A review list, not a defect list. |

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

## AZP002 — Object-addressing endpoint cannot be scoping to the caller (4)

- `GET /api/invoices/{id:guid}`
- `GET /api/tenants/{tenantId}/documents/{documentId}`
- `GET /api/legacy-invoices/{invoiceId}`
- `GET /api/orders/{orderId}`

**Fix:** Enforce ownership server-side: derive the owner from the authenticated principal
rather than the request, or apply a resource-based policy via IAuthorizationService.
```

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

A handler that never touches `User`, `ClaimsPrincipal`, `HttpContext` or `IAuthorizationService`
has no way of knowing who is calling, so it **cannot** be filtering by them. That is a hard
constraint, not a guess, and those endpoints are reported as **AZP002**.

Everything else — handlers that do reference the caller, and handlers that could not be read —
goes to **AZP005** for review.

## What it does not do

It reports where the ownership check is *missing*, not whether a check that exists is *correct*.
An endpoint with a resource-based policy passes; proving that policy right is your tests' job.

The known blind spots:

- If your handler calls a service that reaches the principal internally via `IHttpContextAccessor`,
  the handler's own IL never mentions it, and AuthzProbe reports AZP002. Ownership checks one level
  down the call graph are not followed.
- Only route parameters are examined. An identifier passed in the query string or a request body is
  the same defect and is not seen.
- Razor Pages handlers are not inspected, so object-addressing pages land in AZP005 rather than
  AZP002.
- A handler that merely reads the principal — logging `User.Identity.Name`, say — counts as
  principal-aware and drops from AZP002 to AZP005. The check is a capability test, not a proof that
  the value is used for filtering.

## Try it

From the repository root:

```bash
cd authzprobe
dotnet run --project samples/SampleApi -- --probe-only
```

The sample maps thirteen endpoints across minimal APIs and controllers. Nine raise a finding —
including a policy named `MustOwnTheRecord` that enforces nothing beyond authentication — and the
probe exits non-zero.

Run the tests the same way:

```bash
dotnet test
```

## Targets

`net8.0`, `net9.0` and `net10.0` (current LTS), with the test suite running against all three.
MIT licensed.
