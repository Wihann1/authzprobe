using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SampleApi.Controllers;

/// <summary>
/// Controller-based endpoints. These reach the routing table by a different path from
/// minimal APIs, so the sample maps both — a scanner that only understands one of them
/// would report a clean surface for half of the real world.
/// </summary>
[ApiController]
[Authorize]
[Route("api")]
public sealed class OrdersController : ControllerBase
{
    /// <summary>AZP002: nothing here can tell who is calling.</summary>
    [HttpGet("orders/{orderId}")]
    public IActionResult GetOrder(string orderId) => Ok(new { orderId });

    /// <summary>AZP005: reads the caller, so it may be scoping in its body.</summary>
    [HttpGet("receipts/{receiptId}")]
    public IActionResult GetReceipt(string receiptId) =>
        Ok(new { receiptId, owner = User.Identity?.Name });
}
