using System.IdentityModel.Tokens.Jwt;
using System.Security;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace APISecurity.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public AuthenticationController(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    // equivalent to creating a class- props with username and password, and a constructor
    public record AuthenticationData(string? UserName, string? Password);

    public record UserData(int UserId, string UserName, string Title, string EmployeeId);

    // api/authentication/token
    [HttpPost("token")]
    [AllowAnonymous] // Because in program.cs we are making sure with the fallback policy
    // that a user needs to be auth'd. We need this so that they don't have to log in. 
    public ActionResult<UserData> Authenticate([FromBody] AuthenticationData data)
    {
        // validate username and password
        var user = ValidateCredentials(data);
        if (user == null)
        {
            return Unauthorized();
        }

        // Generate token now
        var token = GenerateToken(user);
        return Ok(token);
    }

    private string GenerateToken(UserData user)
    {
        var secretKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration.GetValue<string>("Authentication:SecretKey")));
        var signingCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

        // claims
        // data points about the user that we verify
        // id and username in this instance
        List<Claim> claims = new List<Claim>();
        claims.Add(new(JwtRegisteredClaimNames.Sub,  user.UserId.ToString()));
        claims.Add(new(JwtRegisteredClaimNames.UniqueName, user.UserName));
        claims.Add(new("title", user.Title));
        claims.Add(new("employeeid", user.EmployeeId));


        var token = new JwtSecurityToken(
            _configuration.GetValue<string>("Authentication:Issuer"),
            _configuration.GetValue<string>("Authentication:Audience"),
            claims,
            DateTime.UtcNow, // when this token becomes valid
            DateTime.UtcNow.AddMinutes(1), // when the token will expire
             signingCredentials);

        return new JwtSecurityTokenHandler().WriteToken(token);

    }

    private UserData? ValidateCredentials(AuthenticationData data)
    {
        // Would probably do a database thing here -- 


        // THIS IS NOT PRODUCTION CODE - THIS IS ONLY A DEMO - DO NOT USE IN REAL LIFE
        if (CompareValues(data.UserName, "tcorey") && CompareValues(data.Password, "Test123"))
        {
            // We validated username here already, so we know it's not null. 
            var userData = new UserData(1, data.UserName!, "Business Owner", "E001");
            return userData;
        }

        if (CompareValues(data.UserName, "sstorm") && CompareValues(data.Password, "Test123"))
        {
            // We validated username here already, so we know it's not null. 
            var userData = new UserData(1, data.UserName!, "Head of Development", "E003");
            return userData;
        }
        return null;

    }

    private bool CompareValues(string? actual, string expected)
    {
        if (actual is not null)
        {
            if (actual.Equals(expected))
            {
                return true;
            }
        }

        return false;
    }
}

