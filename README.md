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
| **AZP002** | Warning | Endpoint takes an object identifier, requires only "signed in", **and its handler never references the caller** — so it cannot be filtering by them. |
| **AZP003** | Warning | Explicitly anonymous *and* addresses a specific object. Guessable ids are readable by anyone. |
| **AZP004** | Info | Object-addressing endpoint guarded only by a role. A role says what kind of user you are, never which rows are yours. |
| **AZP005** | Info | Object-addressing endpoint with no declarative scoping, but its handler *does* touch the caller — or could not be inspected. A review list, not a defect list. |

Reads inline policies too — `RequireAuthorization(p => p.RequireRole("Admin"))` compiles the role
into an `AuthorizationPolicy` where it never appears on `IAuthorizeData`, which is exactly the sort
of thing a naive scan misses.

## Sample output

```
# AuthzProbe report

- Endpoints scanned: **10**
- Findings: **6** (1 error, 3 warning, 2 info)
- Result: **FAIL**

## AZP002 — Object-addressing endpoint cannot be scoping to the caller (2)

- `GET /api/invoices/{id:guid}`
- `GET /api/tenants/{tenantId}/documents/{documentId}`

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

`health*`, `swagger*`, `.well-known/*`, `_framework/*` and `error*` are ignored by default.

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

The known blind spot: if your handler calls a service that reaches the principal internally via
`IHttpContextAccessor`, the handler's own IL never mentions it, and AuthzProbe will report AZP002.
Ownership checks that happen one level down the call graph are not followed.

## Try it

From the repository root:

```bash
cd authzprobe
dotnet run --project samples/SampleApi -- --probe-only
```

The sample maps nine endpoints — four defective, five clean — and exits non-zero.

Run the tests the same way:

```bash
dotnet test
```

## Targets

`net8.0`, `net9.0` and `net10.0` (current LTS). MIT licensed.
