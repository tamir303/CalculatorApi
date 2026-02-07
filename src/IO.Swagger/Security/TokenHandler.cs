using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using IO.Swagger.Configuration;

namespace IO.Swagger.Security;

/// <summary>
/// Interface for JWT token creation and management
/// </summary>
public interface ITokenHandler
{
    /// <summary>
    /// Creates a new JWT access token for a user
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="username">Username</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>Token string and expiration time in seconds</returns>
    Task<(string Token, int ExpiresInSeconds)> CreateAccessTokenAsync(Guid userId, string username, CancellationToken ct = default);

    /// <summary>
    /// Retrieves an existing valid token for a user from Redis cache
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>Existing token and expiration, or null if not found</returns>
    Task<(string Token, int ExpiresInSeconds)?> GetExistingTokenAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Revokes a token by removing it from Redis cache
    /// </summary>
    /// <param name="jti">JWT ID to revoke</param>
    /// <param name="ct">Cancellation token</param>
    Task RevokeAsync(string jti, CancellationToken ct = default);
}

/// <summary>
/// JWT token handler for creating, validating, and revoking access tokens
/// </summary>
public sealed class TokenHandler : ITokenHandler
{
    private readonly JwtOptions _jwt;
    private readonly RedisOptions _redisOptions;
    private readonly IDatabase _redis;

    /// <summary>
    /// Initializes a new instance of the TokenHandler
    /// </summary>
    /// <param name="jwt">JWT configuration options</param>
    /// <param name="redisOptions">Redis configuration options</param>
    /// <param name="mux">Redis connection multiplexer</param>
    public TokenHandler(
        IOptions<JwtOptions> jwt,
        IOptions<RedisOptions> redisOptions,
        IConnectionMultiplexer mux)
    {
        _jwt = jwt.Value;
        _redisOptions = redisOptions.Value;
        _redis = mux.GetDatabase();
    }

    /// <inheritdoc />
    public async Task<(string Token, int ExpiresInSeconds)> CreateAccessTokenAsync(
        Guid userId,
        string username,
        CancellationToken ct)
    {
        // Check for and revoke any existing valid token for this user before creating a new one
        var userTokenKey = $"{_redisOptions.InstancePrefix}user:{userId}:token";
        var existingTokenStr = await _redis.StringGetAsync(userTokenKey);

        if (!existingTokenStr.IsNullOrEmpty)
        {
            try
            {
                // Attempt to parse the old token to get its JTI for revocation
                var handler = new JwtSecurityTokenHandler();
                if (handler.CanReadToken(existingTokenStr))
                {
                    var jwtToken = handler.ReadJwtToken(existingTokenStr);
                    if (!string.IsNullOrEmpty(jwtToken.Id))
                    {
                        await RevokeAsync(jwtToken.Id, ct);
                    }
                }
            }
            catch
            {
                // If we can't parse the old token, we can't revoke it safely by JTI. 
            }
        }

        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(_jwt.ExpirationMinutes);

        // Generate unique token ID
        var jti = Guid.NewGuid().ToString("N");

        // Build JWT claims
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new(JwtRegisteredClaimNames.UniqueName, username),
            new(JwtRegisteredClaimNames.Jti, jti),
            new(JwtRegisteredClaimNames.Iat, ToUnixTimeSeconds(now).ToString(), ClaimValueTypes.Integer64),

            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(ClaimTypes.Name, username)
        };

        // Create signing credentials from hex-encoded key
        var keyBytes = Convert.FromHexString(_jwt.SigningKey);
        var key = new SymmetricSecurityKey(keyBytes);
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // Create JWT token
        var tokenObj = new JwtSecurityToken(
            issuer: _jwt.Issuer,
            audience: _jwt.Audience,
            claims: claims,
            notBefore: now,
            expires: expires,
            signingCredentials: creds);

        var token = new JwtSecurityTokenHandler().WriteToken(tokenObj);

        // Store token in Redis with TTL
        var ttl = TimeSpan.FromMinutes(_jwt.ExpirationMinutes);

        // Store by JTI for token validation
        var jtiKey = $"{_redisOptions.InstancePrefix}token:{jti}";
        await _redis.StringSetAsync(jtiKey, userId.ToString(), ttl);

        // Store by user ID for retrieving existing tokens
        await _redis.StringSetAsync(userTokenKey, token, ttl);

        return (token, (int)ttl.TotalSeconds);
    }

    /// <inheritdoc />
    public async Task<(string Token, int ExpiresInSeconds)?> GetExistingTokenAsync(Guid userId, CancellationToken ct = default)
    {
        var userTokenKey = $"{_redisOptions.InstancePrefix}user:{userId}:token";
        var existingToken = await _redis.StringGetAsync(userTokenKey);

        if (existingToken.IsNullOrEmpty)
            return null;

        // Get remaining TTL
        var ttl = await _redis.KeyTimeToLiveAsync(userTokenKey);

        if (!ttl.HasValue || ttl.Value.TotalSeconds <= 0)
            return null;

        return (existingToken.ToString(), (int)ttl.Value.TotalSeconds);
    }

    /// <inheritdoc />
    public async Task RevokeAsync(string jti, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(jti)) return;

        var redisKey = $"{_redisOptions.InstancePrefix}token:{jti}";
        await _redis.KeyDeleteAsync(redisKey);
    }

    private static long ToUnixTimeSeconds(DateTime utc)
        => new DateTimeOffset(utc).ToUnixTimeSeconds();
}