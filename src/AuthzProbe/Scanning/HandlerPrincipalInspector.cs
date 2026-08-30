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
/// from the other direction: rather than trying to prove a check exists, it proves one
/// <em>cannot</em>. A handler whose IL never references the authenticated principal has
/// no way to know who is calling, so it cannot be filtering by them.
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
        var (found, complete) = ReferencesPrincipal(target, il);

        if (found)
        {
            return HandlerInspection.PrincipalAware;
        }

        return complete ? HandlerInspection.PrincipalBlind : HandlerInspection.Unknown;
    }

    private static bool IsPrincipalType(Type type) =>
        PrincipalTypeNames.Contains(type.Name, StringComparer.Ordinal)
        || string.Equals(type.Name, "HttpContext", StringComparison.Ordinal);

    /// <summary>
    /// Returns whether a principal reference was found, and whether the whole body was
    /// walked. An incomplete walk cannot support a negative conclusion.
    /// </summary>
    private static (bool Found, bool Complete) ReferencesPrincipal(MethodInfo method, byte[] il)
    {
        var module = method.Module;
        var typeArgs = SafeGenericArguments(method.DeclaringType);
        var methodArgs = method.IsGenericMethodDefinition ? method.GetGenericArguments() : [];

        var (tokens, complete) = WalkTokens(il);

        foreach (var token in tokens)
        {
            MemberInfo? member;
            try
            {
                member = module.ResolveMember(token, typeArgs, methodArgs);
            }
            catch (Exception)
            {
                // Tokens from other modules or malformed reads: skip, don't fail the scan.
                continue;
            }

            if (member is null)
            {
                continue;
            }

            if (PrincipalMemberNames.Contains(member.Name, StringComparer.Ordinal))
            {
                return (true, complete);
            }

            if (member is Type t && IsPrincipalType(t))
            {
                return (true, complete);
            }

            var declaring = member.DeclaringType;
            if (declaring is not null && IsPrincipalType(declaring))
            {
                return (true, complete);
            }
        }

        return (false, complete);
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
        var tokens = new List<int>();
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
                    return (tokens, false);
                }

                code = (short)(0xFE00 | il[pos]);
                pos++;
            }

            if (!OpCodes.TryGetValue(code, out var op))
            {
                // Unrecognised opcode means alignment is lost. Report the walk as
                // incomplete so the caller does not treat the absence of a principal
                // reference as proof of absence.
                return (tokens, false);
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
                    return (tokens, false);
                }

                var count = BitConverter.ToInt32(il, pos);

                // The count comes from the byte stream. A negative or oversized value
                // means we are not where we think we are; overflowing the arithmetic
                // would be worse than stopping.
                if (count < 0 || count > (il.Length - pos - 4) / 4)
                {
                    return (tokens, false);
                }

                pos += 4 + (count * 4);
                continue;
            }

            if (pos + operandSize > il.Length)
            {
                return (tokens, false);
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

        return (tokens, true);
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
