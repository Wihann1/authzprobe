using System.Security.Claims;
using AuthzProbe.Model;
using AuthzProbe.Scanning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthzProbe.Tests;

/// <summary>
/// Exercises the handler inspector directly, including the shapes that routing-metadata
/// analysis alone gets wrong: async state machines, controllers, and handlers that reach
/// the principal by several different routes.
/// </summary>
public class HandlerPrincipalInspectorTests
{
    // --- handlers that cannot see the caller ---------------------------------------

    private static string Blind(string id) => id;

    private static async Task<string> BlindAsync(string id)
    {
        await Task.Yield();
        return id + "!";
    }

    // --- handlers that can ---------------------------------------------------------

    private static string TakesPrincipal(string id, ClaimsPrincipal user) => id + user.Identity?.Name;

    private static string TakesHttpContext(string id, HttpContext ctx) => id + ctx.User.Identity?.Name;

    private static string ReadsUserFromContext(string id, HttpContext ctx)
    {
        var name = ctx.User.Identity?.Name;
        return id + name;
    }

    private static async Task<string> ReadsUserAsync(string id, HttpContext ctx)
    {
        await Task.Yield();
        var name = ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return id + name;
    }

    private static async Task<bool> UsesAuthorizationService(
        string id, IAuthorizationService authz, ClaimsPrincipal user)
    {
        var result = await authz.AuthorizeAsync(user, id, "Owner");
        return result.Succeeded;
    }

    private static HandlerInspection InspectLocal(string name) =>
        HandlerPrincipalInspector.Inspect(
            typeof(HandlerPrincipalInspectorTests).GetMethod(
                name,
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static));

    [Theory]
    [InlineData(nameof(Blind))]
    [InlineData(nameof(BlindAsync))]
    public void Handlers_that_never_touch_the_caller_are_blind(string method) =>
        Assert.Equal(HandlerInspection.PrincipalBlind, InspectLocal(method));

    [Theory]
    [InlineData(nameof(TakesPrincipal))]
    [InlineData(nameof(TakesHttpContext))]
    [InlineData(nameof(ReadsUserFromContext))]
    [InlineData(nameof(ReadsUserAsync))]
    [InlineData(nameof(UsesAuthorizationService))]
    public void Handlers_that_can_see_the_caller_are_aware(string method) =>
        Assert.Equal(HandlerInspection.PrincipalAware, InspectLocal(method));

    [Fact]
    public void A_null_handler_is_unknown_rather_than_blind() =>
        Assert.Equal(HandlerInspection.Unknown, HandlerPrincipalInspector.Inspect(null));

    [Fact]
    public void An_abstract_method_is_unknown_rather_than_blind()
    {
        var method = typeof(AbstractHandler).GetMethod(nameof(AbstractHandler.Handle));

        Assert.Equal(HandlerInspection.Unknown, HandlerPrincipalInspector.Inspect(method));
    }

    [Fact]
    public void An_interface_method_is_unknown_rather_than_blind()
    {
        var method = typeof(IHandler).GetMethod(nameof(IHandler.Handle));

        Assert.Equal(HandlerInspection.Unknown, HandlerPrincipalInspector.Inspect(method));
    }

    [Fact]
    public void Controller_action_reading_User_is_aware()
    {
        var method = typeof(SampleController).GetMethod(nameof(SampleController.Scoped));

        Assert.Equal(HandlerInspection.PrincipalAware, HandlerPrincipalInspector.Inspect(method));
    }

    [Fact]
    public void Controller_action_ignoring_User_is_blind()
    {
        var method = typeof(SampleController).GetMethod(nameof(SampleController.Unscoped));

        Assert.Equal(HandlerInspection.PrincipalBlind, HandlerPrincipalInspector.Inspect(method));
    }

    [Fact]
    public void Async_controller_action_reading_User_is_aware()
    {
        var method = typeof(SampleController).GetMethod(nameof(SampleController.ScopedAsync));

        Assert.Equal(HandlerInspection.PrincipalAware, HandlerPrincipalInspector.Inspect(method));
    }

    [Fact]
    public void Handler_reaching_the_principal_through_a_local_function_is_aware()
    {
        // The local function is compiled into the same enclosing method body, so the
        // reference is still visible in its IL.
        var method = typeof(HandlerPrincipalInspectorTests).GetMethod(
            nameof(ViaLocalFunction),
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        Assert.Equal(HandlerInspection.PrincipalAware, HandlerPrincipalInspector.Inspect(method));
    }

    private static string ViaLocalFunction(string id, HttpContext ctx)
    {
        return Owner() + id;

        string? Owner() => ctx.User.Identity?.Name;
    }

    [Fact]
    public void Inspection_is_stable_across_repeated_calls()
    {
        // The opcode table is a shared static; make sure nothing mutates per call.
        var first = InspectLocal(nameof(ReadsUserFromContext));

        for (var i = 0; i < 50; i++)
        {
            Assert.Equal(first, InspectLocal(nameof(ReadsUserFromContext)));
        }
    }

    [Fact]
    public void Inspecting_many_handlers_is_fast_enough_for_startup()
    {
        var method = typeof(SampleController).GetMethod(nameof(SampleController.ScopedAsync));
        var sw = System.Diagnostics.Stopwatch.StartNew();

        for (var i = 0; i < 1_000; i++)
        {
            HandlerPrincipalInspector.Inspect(method);
        }

        sw.Stop();

        // 1,000 inspections stands in for a very large API surface. This runs once at
        // startup, so the bar is "not noticeable", not "fast".
        Assert.True(sw.ElapsedMilliseconds < 5_000, $"took {sw.ElapsedMilliseconds}ms");
    }

    // --- fixtures ------------------------------------------------------------------

    private abstract class AbstractHandler
    {
        public abstract string Handle(string id);
    }

    private interface IHandler
    {
        string Handle(string id);
    }

    private class SampleController : ControllerBase
    {
        public IActionResult Unscoped(string id) => Ok(new { id });

        public IActionResult Scoped(string id) => Ok(new { id, who = User.Identity?.Name });

        public async Task<IActionResult> ScopedAsync(string id)
        {
            await Task.Yield();
            return Ok(new { id, who = User.Identity?.Name });
        }
    }
}
