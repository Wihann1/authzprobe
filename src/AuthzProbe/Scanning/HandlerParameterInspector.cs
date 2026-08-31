using System.Reflection;

namespace AuthzProbe.Scanning;

/// <summary>Where an endpoint takes the identifier of the object it acts on.</summary>
public sealed record HandlerIdentifiers
{
    /// <summary>Identifier-shaped parameters bound from the query string.</summary>
    public IReadOnlyList<string> Query { get; init; } = [];

    /// <summary>Identifier-shaped properties on a type bound from the request body.</summary>
    public IReadOnlyList<string> Body { get; init; } = [];

    /// <summary>Nothing found.</summary>
    public static HandlerIdentifiers None { get; } = new();
}

/// <summary>
/// Finds object identifiers an endpoint accepts somewhere other than its route.
/// </summary>
/// <remarks>
/// <c>GET /api/invoices/{id}</c> and <c>PUT /api/invoices</c> with the id in the body are the
/// same defect wearing different clothes, but only the first is visible in a route template.
/// The handler's signature is where the rest of them live, and the handler's
/// <see cref="MethodInfo"/> is already in hand for the IL walk.
/// </remarks>
public static class HandlerParameterInspector
{
    /// <summary>Types that carry no caller-supplied identifier, whatever they are named.</summary>
    private static readonly string[] NonDataTypeNames =
    [
        "HttpContext", "HttpRequest", "HttpResponse", "CancellationToken",
        "ClaimsPrincipal", "IFormFile", "IFormFileCollection", "IFormCollection",
        "Stream", "PipeReader", "BindingInfo"
    ];

    private const int MaxBodyPropertiesInspected = 200;

    /// <summary>
    /// Inspects the handler signatures for identifiers the route template does not show.
    /// </summary>
    /// <param name="handlers">The methods behind the endpoint.</param>
    /// <param name="routeParameters">
    /// Names already accounted for by the route, so a parameter bound from the route is not
    /// reported a second time as a query identifier.
    /// </param>
    public static HandlerIdentifiers Inspect(
        IReadOnlyCollection<MethodInfo> handlers,
        IReadOnlyList<string> routeParameters)
    {
        ArgumentNullException.ThrowIfNull(handlers);
        ArgumentNullException.ThrowIfNull(routeParameters);

        if (handlers.Count == 0)
        {
            return HandlerIdentifiers.None;
        }

        var query = new List<string>();
        var body = new List<string>();

        foreach (var handler in handlers)
        {
            ParameterInfo[] parameters;
            try
            {
                parameters = handler.GetParameters();
            }
            catch (Exception)
            {
                continue;
            }

            foreach (var parameter in parameters)
            {
                Classify(parameter, routeParameters, query, body);
            }
        }

        return new HandlerIdentifiers
        {
            Query = query.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            Body = body.Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
        };
    }

    private static void Classify(
        ParameterInfo parameter,
        IReadOnlyList<string> routeParameters,
        List<string> query,
        List<string> body)
    {
        var type = parameter.ParameterType;

        if (IsInjectedService(parameter, type) || IsNonData(type))
        {
            return;
        }

        if (IsSimple(type))
        {
            var name = BoundName(parameter);

            // A parameter matching a route token is bound from the route and is already
            // counted there.
            if (routeParameters.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                return;
            }

            if (ResourceIdentifierHeuristics.LooksLikeResourceIdentifier(name))
            {
                query.Add(name);
            }

            return;
        }

        // A complex parameter that is not a service is model-bound from the body. Its
        // identifier-shaped properties are what the caller gets to choose.
        if (!IsApplicationType(type))
        {
            return;
        }

        PropertyInfo[] properties;
        try
        {
            properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        }
        catch (Exception)
        {
            return;
        }

        foreach (var property in properties.Take(MaxBodyPropertiesInspected))
        {
            if (!property.CanRead
                || !IsSimple(property.PropertyType)
                || !ResourceIdentifierHeuristics.LooksLikeResourceIdentifier(property.Name))
            {
                continue;
            }

            body.Add(property.Name);
        }
    }

    /// <summary>The name the value binds under, honouring an explicit binding-source name.</summary>
    private static string BoundName(ParameterInfo parameter)
    {
        foreach (var attribute in parameter.GetCustomAttributes(inherit: true))
        {
            var attributeName = attribute.GetType().Name;

            if (attributeName is not ("FromQueryAttribute" or "FromRouteAttribute" or "FromHeaderAttribute"))
            {
                continue;
            }

            // IModelNameProvider.Name, read without taking a dependency on MVC's abstractions.
            if (attribute.GetType().GetProperty("Name")?.GetValue(attribute) is string { Length: > 0 } named)
            {
                return named;
            }
        }

        return parameter.Name ?? string.Empty;
    }

    private static bool IsInjectedService(ParameterInfo parameter, Type type)
    {
        if (parameter.GetCustomAttributes(inherit: true)
            .Any(a => a.GetType().Name is "FromServicesAttribute" or "FromKeyedServicesAttribute"))
        {
            return true;
        }

        // Services are all but always injected through an interface, and an interface is
        // never model-bound from a request.
        return type.IsInterface || typeof(Delegate).IsAssignableFrom(type);
    }

    private static bool IsNonData(Type type) =>
        NonDataTypeNames.Contains(type.Name, StringComparer.Ordinal);

    private static bool IsSimple(Type type)
    {
        type = Nullable.GetUnderlyingType(type) ?? type;

        return type.IsPrimitive
               || type.IsEnum
               || type == typeof(string)
               || type == typeof(Guid)
               || type == typeof(decimal)
               || type == typeof(DateTime)
               || type == typeof(DateTimeOffset)
               || type == typeof(DateOnly)
               || type == typeof(TimeOnly);
    }

    /// <summary>
    /// True for a type belonging to the application rather than the framework. Framework types
    /// reaching a handler are plumbing, not the caller's request model.
    /// </summary>
    private static bool IsApplicationType(Type type)
    {
        var ns = type.Namespace ?? string.Empty;

        return !ns.StartsWith("System", StringComparison.Ordinal)
               && !ns.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal)
               && !ns.StartsWith("Microsoft.Extensions", StringComparison.Ordinal);
    }
}
