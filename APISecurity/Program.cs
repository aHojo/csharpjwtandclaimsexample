using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using APISecurity.Constants;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// What the user has access to. 
builder.Services.AddAuthorization(opts =>
{
    // If there are no other policies provided, the user needs to be at least authenticated.
    // default [Authorize] does not matter anymore.
    // if you don't want it add [AllowAuthorization] to controllers or routes
    opts.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    opts.AddPolicy(PolicyConstants.MustHaveEmployeeId, policy =>
    {
        policy.RequireClaim("employeeid");
    });
    opts.AddPolicy(PolicyConstants.MustBeTheOwner, policy =>
    {
        policy.RequireClaim("title", "Business Owner");
    });
    opts.AddPolicy(PolicyConstants.MustBeAVeteranEmployee, policy =>
    {
        policy.RequireClaim("employeeid", "E001", "E002", "E003");
    });
});



// This is how we add validation to our jwt web token 
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer(opts =>
    {
        opts.TokenValidationParameters = new()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration.GetValue<string>("Authentication:Issuer"),
            ValidAudience = builder.Configuration.GetValue<string>("Authentication:Audience"),
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(builder.Configuration.GetValue<string>("Authentication:SecretKey")))
        };

    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication(); // order matters
app.UseAuthorization();

app.MapControllers();

app.Run();
