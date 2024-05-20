namespace TokenProvider.Infrastructure.Models;

public class AccessTokenResult
{
    public int? StatusCode { get; set; }
    public string? Token { get; set; }
    public string? Error { get; set; }
}
