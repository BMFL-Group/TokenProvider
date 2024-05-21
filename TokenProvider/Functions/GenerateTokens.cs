using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using TokenProvider.Infrastructure.Models;
using TokenProvider.Infrastructure.Services;

namespace TokenProvider.Functions;

public class GenerateTokens(ILogger<GenerateTokens> logger, ITokenService tokenService)
{
    private readonly ILogger<GenerateTokens> _logger = logger;
    private readonly ITokenService _tokenService = tokenService;

    [Function("GenerateTokens")]
    public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post", Route = "token/generate")] HttpRequest req)
    {
        _logger.LogInformation("Starting RefreshTokens function");

        var body = await new StreamReader(req.Body).ReadToEndAsync();
        var tokenRequest = JsonConvert.DeserializeObject<TokenRequest>(body);

        if (tokenRequest == null || tokenRequest.UserId == null || tokenRequest.Email == null)
        {
            _logger.LogWarning("Invalid token request");
            return new BadRequestObjectResult(new { Error = "Please provide a valid user Id and email." });
        }

        try
        {
            _logger.LogInformation("Deserialized token request");

            RefreshTokenResult refreshTokenResult = null!;
            AccessTokenResult accessTokenResult = null!;

            using var ctsTimeOut = new CancellationTokenSource(TimeSpan.FromSeconds(300));
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctsTimeOut.Token, req.HttpContext.RequestAborted);

            _logger.LogInformation("Request cookies: {Cookies}", JsonConvert.SerializeObject(req.HttpContext.Request.Cookies));

            if (!req.HttpContext.Request.Cookies.TryGetValue("refreshToken", out var refreshToken))
            {
                _logger.LogWarning("Refresh token not found in cookies or is invalid, generating a new one");
                refreshTokenResult = await _tokenService.GenerateRefreshTokenAsync(tokenRequest.UserId, cts.Token);
            }
            else
            {
                _logger.LogInformation("Found refresh token in cookies: {RefreshToken}", refreshToken);
                refreshTokenResult = await _tokenService.GetRefreshTokenAsync(refreshToken, cts.Token);
                if (refreshTokenResult == null)
                {
                    _logger.LogWarning("Refresh token is invalid, generating a new one");
                    refreshTokenResult = await _tokenService.GenerateRefreshTokenAsync(tokenRequest.UserId, cts.Token);
                }
                else if (refreshTokenResult.ExpiryDate < DateTime.Now)
                {
                    _logger.LogWarning("Refresh token has expired, generating a new one");
                    refreshTokenResult = await _tokenService.GenerateRefreshTokenAsync(tokenRequest.UserId, cts.Token);
                }
            }

            accessTokenResult = _tokenService.GenerateAccessToken(tokenRequest, refreshTokenResult.Token);

            if (refreshTokenResult.Token != null && refreshTokenResult.CookieOptions != null)
            {
                req.HttpContext.Response.Cookies.Append("refreshToken", refreshTokenResult.Token, refreshTokenResult.CookieOptions);
                _logger.LogInformation("New refresh token set in cookies");
            }

            if (accessTokenResult != null && accessTokenResult.Token != null && refreshTokenResult.Token != null)
            {
                _logger.LogInformation("Successfully generated access token and refresh token");
                return new OkObjectResult(new { AccessToken = accessTokenResult.Token, RefreshToken = refreshTokenResult.Token });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while processing the refresh token request");
        }

        return new ObjectResult(new { Error = "An unexpected error occurred while generating tokens." }) { StatusCode = 500 };
    }
}
