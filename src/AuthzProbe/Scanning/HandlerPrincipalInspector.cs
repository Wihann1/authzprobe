using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using AuthzProbe.Model;

namespace AuthzProbe.Scanning;

/// <summary>
/// Decides whether an endpoint's handler is even <em>capable</em> of scoping a result
/// to the caller.
/// </summary>
/// <remarks>
/// Routing metadata cannot see inside a handler, so an endpoint that checks ownership
/// in its body looks identical to one that checks nothing. This closes most of that gap
/// from the other direction: rather than looking for evidence that a check exists, it looks
/// for evidence that none can. A handler whose IL never references the authenticated principal,
/// and which calls nothing that does, is unlikely to be filtering by the caller — though a
/// service injected as an interface can reach the principal without the handler naming it, so
/// this is evidence rather than proof.
/// </remarks>
public static class HandlerPrincipalInspector
{
    private static readonly Dictionary<short, OpCode> OpCodes = BuildOpCodeTable();

    /// <summary>Type and member names that indicate the handler can see the caller.</summary>
    private static readonly string[] PrincipalTypeNames =
    [
        "ClaimsPrincipal", "ClaimsIdentity", "IIdentity", "Claim",
        "IAuthorizationService", "IHttpContextAccessor", "AuthorizationResult"
    ];

    private static readonly string[] PrincipalMemberNames =
    [
        "get_User", "AuthorizeAsync", "get_HttpContext"
    ];

    /// <summary>
    /// How many called methods are followed one level deep. A handler calling more distinct
    /// application methods than this is doing too much to reason about anyway.
    /// </summary>
    private const int MaxCalleesFollowed = 64;

    /// <summary>
    /// Inspects several handler methods that share one endpoint, as a Razor Page's
    /// <c>OnGet</c>/<c>OnPost</c> handlers do.
    /// </summary>
    /// <remarks>
    /// One aware handler makes the endpoint aware: the conservative reading is the one that
    /// avoids claiming a defect. Only when every handler was read and none touches the caller
    /// is the endpoint blind.
    /// </remarks>
    public static HandlerInspection InspectAll(IReadOnlyCollection<MethodInfo> handlers)
    {
        ArgumentNullException.ThrowIfNull(handlers);

        if (handlers.Count == 0)
        {
            return HandlerInspection.Unknown;
        }

        var results = handlers.Select(Inspect).ToArray();

        if (results.Any(r => r is HandlerInspection.PrincipalAware))
        {
            return HandlerInspection.PrincipalAware;
        }

        return results.All(r => r is HandlerInspection.PrincipalBlind)
            ? HandlerInspection.PrincipalBlind
            : HandlerInspection.Unknown;
    }

    /// <summary>Inspects the handler behind an endpoint.</summary>
    public static HandlerInspection Inspect(MethodInfo? handler)
    {
        if (handler is null)
        {
            return HandlerInspection.Unknown;
        }

        // A ClaimsPrincipal or HttpContext parameter is a direct signal, no IL needed.
        if (handler.GetParameters().Any(p => IsPrincipalType(p.ParameterType)))
        {
            return HandlerInspection.PrincipalAware;
        }

        // For an async method the real body lives in the compiler-generated state
        // machine; the method itself only contains the kickoff.
        var target = handler;
        var stateMachine = handler.GetCustomAttribute<AsyncStateMachineAttribute>()?.StateMachineType
                           ?? handler.GetCustomAttribute<IteratorStateMachineAttribute>()?.StateMachineType;

        if (stateMachine is not null)
        {
            target = stateMachine.GetMethod(
                "MoveNext",
                BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public) ?? handler;
        }

        byte[]? il;
        try
        {
            il = target.GetMethodBody()?.GetILAsByteArray();
        }
        catch (Exception)
        {
            // Abstract, extern, or otherwise bodiless — we cannot tell either way.
            return HandlerInspection.Unknown;
        }

        if (il is null || il.Length == 0)
        {
            return HandlerInspection.Unknown;
        }

        // A partial walk that missed a principal reference would report PrincipalBlind and
        // present a possibly-safe endpoint as a high-confidence defect. Only claim
        // "blind" when the whole body was read successfully.
        var (members, complete) = ResolveReferencedMembers(target, il);

        // A body that only throws is a stub, not an implementation — an abstract-in-spirit
        // base whose real handler lives in a derived type. ASP.NET Core Identity's page models
        // are built this way: the routed type's handlers throw, and the generic subclass
        // registered at runtime holds the code that reads the principal. Concluding "blind"
        // from a stub reports a safe endpoint as a defect.
        if (IsThrowOnlyStub(il))
        {
            return HandlerInspection.Unknown;
        }

        if (members.Any(IsPrincipalReference))
        {
            return HandlerInspection.PrincipalAware;
        }

        // A handler often delegates the ownership check to a helper it calls directly. One
        // hop covers that without pretending to be a call-graph analyser: if a method this
        // handler calls touches the principal, the handler can be scoping through it.
        if (CallsPrincipalAwareMethod(members))
        {
            return HandlerInspection.PrincipalAware;
        }

        return complete ? HandlerInspection.PrincipalBlind : HandlerInspection.Unknown;
    }

    /// <summary>
    /// Follows calls the handler makes, one level deep, looking for a principal reference in
    /// the callee.
    /// </summary>
    /// <remarks>
    /// Only methods with a readable body are followed, which means a call through an interface
    /// is not: the interface method has no body, and choosing an implementation would require
    /// knowing the container's registrations. A service reached through an injected interface
    /// therefore remains the documented blind spot, one hop or not.
    /// </remarks>
    private static bool CallsPrincipalAwareMethod(IReadOnlyList<MemberInfo> members)
    {
        var examined = 0;

        foreach (var member in members)
        {
            if (examined >= MaxCalleesFollowed)
            {
                return false;
            }

            if (member is not MethodInfo callee || !IsApplicationMethod(callee))
            {
                continue;
            }

            var body = BodyOf(Unwrap(callee));

            if (body is null || body.Length == 0)
            {
                continue;
            }

            examined++;

            var (calleeMembers, _) = ResolveReferencedMembers(Unwrap(callee), body);

            if (calleeMembers.Any(IsPrincipalReference))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>An async or iterator method's real body lives in its state machine.</summary>
    private static MethodInfo Unwrap(MethodInfo method)
    {
        var stateMachine = method.GetCustomAttribute<AsyncStateMachineAttribute>()?.StateMachineType
                           ?? method.GetCustomAttribute<IteratorStateMachineAttribute>()?.StateMachineType;

        if (stateMachine is null)
        {
            return method;
        }

        return stateMachine.GetMethod(
            "MoveNext",
            BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public) ?? method;
    }

    private static byte[]? BodyOf(MethodInfo method)
    {
        try
        {
            return method.GetMethodBody()?.GetILAsByteArray();
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// True for a method belonging to the application. Following framework methods would walk
    /// most of the base class library to no purpose — a framework method that exposes the
    /// principal is already matched directly by name.
    /// </summary>
    private static bool IsApplicationMethod(MethodInfo method)
    {
        var ns = method.DeclaringType?.Namespace ?? string.Empty;

        return !ns.StartsWith("System", StringComparison.Ordinal)
               && !ns.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal)
               && !ns.StartsWith("Microsoft.Extensions", StringComparison.Ordinal);
    }

    private static bool IsPrincipalReference(MemberInfo member)
    {
        if (PrincipalMemberNames.Contains(member.Name, StringComparer.Ordinal))
        {
            return true;
        }

        if (member is Type type && IsPrincipalType(type))
        {
            return true;
        }

        return member.DeclaringType is { } declaring && IsPrincipalType(declaring);
    }

    /// <summary>
    /// True when the body cannot return — it throws and never returns — which makes it a
    /// placeholder rather than a handler.
    /// </summary>
    private static bool IsThrowOnlyStub(byte[] il)
    {
        var (_, complete, sawReturn, sawThrow) = ScanBody(il);

        return complete && sawThrow && !sawReturn;
    }

    private static bool IsPrincipalType(Type type) =>
        PrincipalTypeNames.Contains(type.Name, StringComparer.Ordinal)
        || string.Equals(type.Name, "HttpContext", StringComparison.Ordinal);

    /// <summary>
    /// Resolves the members an IL body references, and reports whether the whole body was
    /// walked. An incomplete walk cannot support a negative conclusion.
    /// </summary>
    private static (IReadOnlyList<MemberInfo> Members, bool Complete) ResolveReferencedMembers(
        MethodInfo method, byte[] il)
    {
        var module = method.Module;
        var typeArgs = SafeGenericArguments(method.DeclaringType);
        var methodArgs = method.IsGenericMethodDefinition ? method.GetGenericArguments() : [];

        var (tokens, complete) = WalkTokens(il);
        var members = new List<MemberInfo>(tokens.Count);

        foreach (var token in tokens)
        {
            try
            {
                if (module.ResolveMember(token, typeArgs, methodArgs) is { } member)
                {
                    members.Add(member);
                }
            }
            catch (Exception)
            {
                // Tokens from other modules or malformed reads: skip, don't fail the scan.
            }
        }

        return (members, complete);
    }

    private static Type[] SafeGenericArguments(Type? type)
    {
        try
        {
            return type?.IsGenericType == true ? type.GetGenericArguments() : [];
        }
        catch (Exception)
        {
            return [];
        }
    }

    /// <summary>
    /// Walks IL and collects the metadata tokens of member-referencing instructions.
    /// The second value reports whether the whole body was decoded; a false there means
    /// the token list is partial and cannot support a negative conclusion.
    /// </summary>
    private static (List<int> Tokens, bool Complete) WalkTokens(byte[] il)
    {
        var (tokens, complete, _, _) = ScanBody(il);
        return (tokens, complete);
    }

    /// <summary>
    /// Walks IL once, collecting member-referencing tokens and noting whether the body can
    /// return and whether it throws.
    /// </summary>
    private static (List<int> Tokens, bool Complete, bool SawReturn, bool SawThrow) ScanBody(byte[] il)
    {
        var tokens = new List<int>();
        var sawReturn = false;
        var sawThrow = false;
        var pos = 0;

        while (pos < il.Length)
        {
            short code = il[pos];
            pos++;

            // Two-byte opcodes are prefixed with 0xFE.
            if (code == 0xFE)
            {
                if (pos >= il.Length)
                {
                    return (tokens, false, sawReturn, sawThrow);
                }

                code = (short)(0xFE00 | il[pos]);
                pos++;
            }

            if (!OpCodes.TryGetValue(code, out var op))
            {
                // Unrecognised opcode means alignment is lost. Report the walk as
                // incomplete so the caller does not treat the absence of a principal
                // reference as proof of absence.
                return (tokens, false, sawReturn, sawThrow);
            }

            if (op.Value == System.Reflection.Emit.OpCodes.Ret.Value)
            {
                sawReturn = true;
            }
            else if (op.Value == System.Reflection.Emit.OpCodes.Throw.Value
                     || op.Value == System.Reflection.Emit.OpCodes.Rethrow.Value)
            {
                sawThrow = true;
            }

            var operandSize = op.OperandType switch
            {
                OperandType.InlineNone => 0,
                OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                OperandType.InlineSwitch => -1,
                _ => 4
            };

            if (operandSize == -1)
            {
                if (pos + 4 > il.Length)
                {
                    return (tokens, false, sawReturn, sawThrow);
                }

                var count = BitConverter.ToInt32(il, pos);

                // The count comes from the byte stream. A negative or oversized value
                // means we are not where we think we are; overflowing the arithmetic
                // would be worse than stopping.
                if (count < 0 || count > (il.Length - pos - 4) / 4)
                {
                    return (tokens, false, sawReturn, sawThrow);
                }

                pos += 4 + (count * 4);
                continue;
            }

            if (pos + operandSize > il.Length)
            {
                return (tokens, false, sawReturn, sawThrow);
            }

            var isTokenOperand = op.OperandType
                is OperandType.InlineMethod
                or OperandType.InlineField
                or OperandType.InlineTok
                or OperandType.InlineType;

            if (isTokenOperand)
            {
                tokens.Add(BitConverter.ToInt32(il, pos));
            }

            pos += operandSize;
        }

        return (tokens, true, sawReturn, sawThrow);
    }

    private static Dictionary<short, OpCode> BuildOpCodeTable()
    {
        var table = new Dictionary<short, OpCode>();

        foreach (var field in typeof(System.Reflection.Emit.OpCodes)
                     .GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            if (field.GetValue(null) is OpCode op)
            {
                table[op.Value] = op;
            }
        }

        return table;
    }
}
