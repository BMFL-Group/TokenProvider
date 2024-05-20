using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using TokenProvider.Infrastructure.Models;
using TokenProvider.Infrastructure.Services;

namespace TokenProvider.Functions;

public class GenerateTokens(ILogger<RefreshTokens> logger, ITokenService tokenService)
{
    private readonly ILogger<RefreshTokens> _logger = logger;
    private readonly ITokenService _tokenService = tokenService;

    [Function("GenerateTokens")]
    public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post", Route = "token/generate")] HttpRequest req)
    {
        var body = await new StreamReader(req.Body).ReadToEndAsync();
        var tokenRequest = JsonConvert.DeserializeObject<TokenRequest>(body);

        if (tokenRequest == null || tokenRequest.UserId == null || tokenRequest.Email == null)
            return new BadRequestObjectResult(new { Error = "Please provide a valid user Id and email." });

        try
        {

            // cts = cancellation token source
            using var ctsTimeOut = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctsTimeOut.Token, req.HttpContext.RequestAborted);

            var accessTokenResult = _tokenService.GenerateAccessToken(tokenRequest, null);

            if (accessTokenResult != null && accessTokenResult.Token != null)
                return new OkObjectResult(new { AccessToken = accessTokenResult.Token });
        }
        catch (Exception ex) { _logger.LogError(ex, "An error occurred while processing the subscription request."); }

        return new ObjectResult(new { Error = "An unexpected error occurred while generating tokens." }) { StatusCode = 500 };
    }
}
