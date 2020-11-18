# Multiple Authentication Scheme .Net Core 3.1 or .Net 5.0
Using both Cookie and JWT Authentication


## Starup.cs
###### ConfigureServices
```
services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                    .AddCookie(x =>
                    {
                        x.LoginPath = "/";
                        x.ExpireTimeSpan = TimeSpan.FromMinutes(Configuration.GetValue<int>("CookieExpiry"));
                    })
                    .AddJwtBearer(x =>
                    {
                        x.RequireHttpsMetadata = false;
                        x.SaveToken = true;
                        x.TokenValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuerSigningKey = true,
                            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Configuration.GetValue<string>("JWTSecret"))),
                            ValidateIssuer = false,
                            ValidateAudience = false
                        };
                    });

            services.AddAuthorization(options =>
            {
                var defaultAuthorizationPolicyBuilder = new AuthorizationPolicyBuilder(CookieAuthenticationDefaults.AuthenticationScheme, JwtBearerDefaults.AuthenticationScheme);
                defaultAuthorizationPolicyBuilder = defaultAuthorizationPolicyBuilder.RequireAuthenticatedUser();
                options.DefaultPolicy = defaultAuthorizationPolicyBuilder.Build();
            });
```
## /api/auth/login
```
public async Task<AuthenticationResult> Login([FromForm] string userName, [FromForm] string password, [FromHeader] string authmode = "")
{
	if (userName != "demo" || password != "demo")
		return new AuthenticationResult { HasError = true, Message = "Either the user name or password is incorrect." };

	var claims = new Claim[]
	{
		new Claim(ClaimTypes.Name, userName)
	};
	

	if(authmode?.ToLower() == "token")
	{
		var tokenHandler = new JwtSecurityTokenHandler();
		var key = Encoding.ASCII.GetBytes(_config.GetValue<string>("JWTSecret"));
		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity(claims, "JWT"),
			Expires = DateTime.UtcNow.AddMinutes(_config.GetValue<int>("JWTExpiry")),
			SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
		};
		var token = tokenHandler.CreateToken(tokenDescriptor);
		var jwt = tokenHandler.WriteToken(token);
		return new AuthenticationResult { Token = jwt };
	}
	else
	{
		ClaimsPrincipal princ = new ClaimsPrincipal(new ClaimsIdentity(claims, "COOKIE"));
		await HttpContext.SignInAsync(princ);
		return new AuthenticationResult();
	}
}
```

## Output:

![image](https://user-images.githubusercontent.com/11205970/99485872-521fb480-2989-11eb-9e31-affb4482e009.png)
![image](https://user-images.githubusercontent.com/11205970/99485937-66fc4800-2989-11eb-99a1-fe637bbf326f.png)

![image](https://user-images.githubusercontent.com/11205970/99485963-724f7380-2989-11eb-80e4-c11e08bdb0e9.png)
![image](https://user-images.githubusercontent.com/11205970/99485983-7aa7ae80-2989-11eb-9e0c-af27627dd3d0.png)
