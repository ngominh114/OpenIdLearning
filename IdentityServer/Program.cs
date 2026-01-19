using IdentityServer.Constants;
using IdentityServer.Data;
using IdentityServer.Models;
using IdentityServer.Repositories;
using IdentityServer.Validators;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
});

builder.Services.AddScoped<IApplicationUserRepository, ApplicationUserRepository>();
builder.Services.AddScoped<IUserValidator<ApplicationUser>, ApplicationUserValidator>();

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"));

    options.UseOpenIddict();
});

// ================= Identity =================
// It will 
// 1. Registers cookie authentication schemes "Identity.Application", "Identity.External",...
// 2. Add functionality of ASP.NET Identity of managing users
// 3. AddDefaultUI will configure the LoginPath,... to the authentication schemes

builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.SignIn.RequireConfirmedAccount = false;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultUI()
    .AddDefaultTokenProviders();

// ================= OpenIddict =================
builder.Services.AddOpenIddict()

    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("/connect/authorize");
        options.SetTokenEndpointUris("/connect/token");
        options.SetEndSessionEndpointUris("/connect/endsession");
        options.SetUserInfoEndpointUris("/connect/userinfo");

        options.RegisterScopes(OpenIddictConstants.Scopes.Email,
                               OpenIddictConstants.Scopes.Profile,
                               OpenIddictConstants.Scopes.OfflineAccess,
                               LocalScopes.EmployeeRead
                               );

        options.DisableAccessTokenEncryption();
        options.AllowAuthorizationCodeFlow()
               .RequireProofKeyForCodeExchange();

        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough();

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();
    })
    .AddClient(options =>
    {
        options.AllowAuthorizationCodeFlow();

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
               .EnableRedirectionEndpointPassthrough();
        options.UseSystemNetHttp();

        options.UseWebProviders()
               .AddGoogle(config =>
               {
                   config.SetRedirectUri("signin-oidc/google");
                   config.AddScopes("openid", "email", "profile");
               })
               .AddFacebook(config =>
               {
                   config.SetRedirectUri("signin-oidc/facebook");
                   config.AddScopes("email");
               });
    });

builder.Services.AddRazorPages();
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

await SeedDataAsync(app);

app.Run();


static async Task SeedDataAsync(WebApplication app)
{
    using var scope = app.Services.CreateScope();

    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await db.Database.MigrateAsync();

    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

    // ---- Client ----
    if (await appManager.FindByClientIdAsync("web-client") == null)
    {
        await appManager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "web-client",
            ClientSecret = "secret",
            DisplayName = "Test Web Client",
            RedirectUris =
            {
                new Uri("https://localhost:5002/signin-oidc")
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://google.com/")
            },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Prefixes.Scope + LocalScopes.EmployeeRead
            }
        });
    }
}