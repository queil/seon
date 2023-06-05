module Queil.Seon.App

open System
open Microsoft.AspNetCore.Authentication.JwtBearer
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Logging
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Configuration
open Giraffe
open Microsoft.IdentityModel.Tokens
open Fli.CE
open Microsoft.Extensions.Options
open Fli
open System.Security.Claims

[<CLIMutable>]
type JwtOptions =
    { Authority: string
      Audience: string
      Issuer: string
      Debug: bool }

[<CLIMutable>]
type AuthOptions = { AllowedSub: string }

[<CLIMutable>]
type CommandOptions = { Path: string; WorkingDir: string }

[<CLIMutable>]
type BasePathOptions = { BasePath: string }

let runHandler: HttpHandler =
    fun (_: HttpFunc) (ctx: HttpContext) ->

        task {
            let opts = ctx.RequestServices.GetRequiredService<IOptions<CommandOptions>>()

            ctx
                .GetLogger()
                .LogInformation("Running: {Path} ({WorkingDir})", opts.Value.Path, opts.Value.WorkingDir)

            try

                let! output =
                    cli {
                        Shell BASH
                        Command(opts.Value.Path)
                        WorkingDirectory(opts.Value.WorkingDir)
                        Output(fun (s:string) -> ctx.GetLogger().LogInformation("log: {Message}", s))
                    }
                    |> Command.executeAsync
                    |> Async.StartAsTask
                output.Error |> Option.iter (fun s -> ctx.GetLogger().LogError("error: {Message}", s))
                
                if output.ExitCode <> 0 then ctx.SetStatusCode 500

                return Some(ctx)

            with exn ->
                ctx.GetLogger().LogError(exn, "Execution error")
                ctx.SetStatusCode 500
                return Some(ctx)
        }

let webApp =
    choose
        [ GET
          >=> choose
              [ route "/health" >=> Successful.OK "Healthy"
                route "/run"
                >=> requiresAuthentication (RequestErrors.UNAUTHORIZED "Bearer" "seon" 401)
                >=> authorizeByPolicyName "SubPolicy" (RequestErrors.FORBIDDEN 403)
                >=> runHandler ]
          setStatusCode 404 ]

// ---------------------------------
// Error handler
// ---------------------------------

let errorHandler (ex: Exception) (logger: ILogger) =
    logger.LogError(ex, "An unhandled exception has occurred while executing the request.")

    clearResponse >=> setStatusCode 500 >=> text ex.Message

// ---------------------------------
// Config and Main
// ---------------------------------

let builder = WebApplication.CreateBuilder()
builder.Host.UseSystemd() |> ignore


let services = builder.Services
let config = builder.Configuration

services
    .Configure<CommandOptions>(config.GetSection("command"))
    .Configure<BasePathOptions>(config)
    .AddOptions()
    .AddCors()
    .AddLogging()
    .AddGiraffe()
    .AddAuthorization(fun (options) ->

        let authOptions = config.GetSection("auth").Get<AuthOptions>()

        options.AddPolicy(
            "SubPolicy",
            fun policy -> policy.RequireClaim(ClaimTypes.NameIdentifier, authOptions.AllowedSub) |> ignore
        )
        |> ignore)
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(fun opts ->
        let jwtOptions = config.GetSection("jwt").Get<JwtOptions>()
        opts.BackchannelHttpHandler <- new System.Net.Http.HttpClientHandler()
        opts.Authority <- jwtOptions.Authority
        opts.SaveToken <- true

        if jwtOptions.Debug then
            opts.Events <-
                JwtBearerEvents(
                    OnMessageReceived =
                        fun x ->
                            task {
                                x.HttpContext
                                    .GetService<ILogger<JwtOptions>>()
                                    .LogDebug("Auth header: {Token}", x.Request.Headers.Authorization)
                            }
                )

        opts.TokenValidationParameters <-
            TokenValidationParameters(
                ValidateIssuer = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidateAudience = true,
                ValidAudience = jwtOptions.Audience,
                ValidIssuer = jwtOptions.Issuer
            ))
|> ignore


builder.Logging.AddConsole().AddDebug() |> ignore

let app = builder.Build()

let basePathOpions = app.Services.GetRequiredService<IOptions<BasePathOptions>>()

let basePath = basePathOpions.Value.BasePath

if basePath <> "" then
    app.UsePathBase(basePathOpions.Value.BasePath) |> ignore

if app.Environment.IsDevelopment() then
    app.UseDeveloperExceptionPage() |> ignore

app
    .UseGiraffeErrorHandler(errorHandler)
    .UseHttpsRedirection()
    .UseAuthentication()
    .UseGiraffe(webApp)

app.Run()
