using AuthzProbe.Scanning;

namespace AuthzProbe.Tests;

public class ResourceIdentifierHeuristicsTests
{
    [Theory]
    [InlineData("id")]
    [InlineData("Id")]
    [InlineData("userId")]
    [InlineData("invoice_id")]
    [InlineData("tenantGuid")]
    [InlineData("documentKey")]
    [InlineData("orderNumber")]
    [InlineData("payslipRef")]
    public void Recognises_object_identifiers(string parameterName) =>
        Assert.True(ResourceIdentifierHeuristics.LooksLikeResourceIdentifier(parameterName));

    [Theory]
    [InlineData("page")]
    [InlineData("pageSize")]
    [InlineData("skip")]
    [InlineData("take")]
    [InlineData("version")]
    [InlineData("culture")]
    [InlineData("format")]
    [InlineData("sort")]
    [InlineData("")]
    public void Rejects_parameters_that_do_not_address_one_object(string parameterName) =>
        Assert.False(ResourceIdentifierHeuristics.LooksLikeResourceIdentifier(parameterName));

    [Theory]
    [InlineData("api/invoices/{id}", new[] { "id" })]
    [InlineData("api/invoices/{id:guid}", new[] { "id" })]
    [InlineData("api/invoices/{id?}", new[] { "id" })]
    [InlineData("api/invoices/{id=5}", new[] { "id" })]
    [InlineData("api/files/{*path}", new[] { "path" })]
    [InlineData("api/tenants/{tenantId}/docs/{docId}", new[] { "tenantId", "docId" })]
    [InlineData("api/health", new string[0])]
    public void Extracts_route_parameters(string pattern, string[] expected) =>
        Assert.Equal(expected, ResourceIdentifierHeuristics.ExtractRouteParameters(pattern));

    [Fact]
    public void Extracting_from_a_null_pattern_returns_empty() =>
        Assert.Empty(ResourceIdentifierHeuristics.ExtractRouteParameters(null));
}
