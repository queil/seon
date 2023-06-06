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
open System.Collections.Generic


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
type SeonEndpoint =
    { Auth: AuthOptions
      Jwt: JwtOptions
      Command: CommandOptions }


[<CLIMutable>]
type SeonConfig =
    { Endpoints: Dictionary<string, SeonEndpoint> }


[<CLIMutable>]
type BasePathOptions = { BasePath: string }

let execute (endpoint: SeonEndpoint) : HttpHandler =
    fun (_: HttpFunc) (ctx: HttpContext) ->

        task {

            ctx
                .GetLogger(ctx.Request.Path)
                .LogInformation("Running: {Path} ({WorkingDir})", endpoint.Command.Path, endpoint.Command.WorkingDir)

            try

                let! output =
                    cli {
                        Shell BASH
                        Command(endpoint.Command.Path)
                        WorkingDirectory(endpoint.Command.WorkingDir)
                        Output(fun (s: string) -> ctx.GetLogger().LogInformation("log: {Message}", s))
                    }
                    |> Command.executeAsync
                    |> Async.StartAsTask

                output.Error
                |> Option.iter (fun s -> ctx.GetLogger().LogError("error: {Message}", s))

                if output.ExitCode <> 0 then
                    ctx.SetStatusCode 500

                return Some(ctx)

            with exn ->
                ctx.GetLogger().LogError(exn, "Execution error")
                ctx.SetStatusCode 500
                return Some(ctx)
        }

let errorHandler (ex: Exception) (logger: ILogger) =
    logger.LogError(ex, "An unhandled exception has occurred while executing the request.")
    clearResponse >=> setStatusCode 500

let builder = WebApplication.CreateBuilder()
builder.Host.UseSystemd() |> ignore

let services = builder.Services

let config =
    ConfigurationBuilder()
        .AddJsonFile("appsettings.json", true)
        .AddEnvironmentVariables()
        .Build()

services
    .Configure<BasePathOptions>(config)
    .AddOptions()
    .AddCors()
    .AddLogging()
    .AddGiraffe()
|> ignore


let seonConfig = config.GetSection("seon").Get<SeonConfig>()


let webApp =
    choose
        [ GET
          >=> choose
              [ route "/health" >=> Successful.OK "Healthy"

                for KeyValue(path, config) in seonConfig.Endpoints do
                    route path
                    >=> requiresAuthentication (challenge path) //"path" (RequestErrors.UNAUTHORIZED path "seon" 401)
                    >=> authorizeByPolicyName $"SubPolicy{path}" (RequestErrors.FORBIDDEN 403)
                    >=> execute config ]
          setStatusCode 404 ]

let authBuilder =
    services
        .AddAuthorization(fun (options) ->

            for KeyValue(path, config) in seonConfig.Endpoints do

                options.AddPolicy(
                    $"SubPolicy{path}",
                    fun policy -> policy.RequireClaim(ClaimTypes.NameIdentifier, config.Auth.AllowedSub) |> ignore
                )
                |> ignore)
        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)

for KeyValue(path, config) in seonConfig.Endpoints do
    authBuilder.AddJwtBearer(
        path,
        fun opts ->

            opts.BackchannelHttpHandler <- new Net.Http.HttpClientHandler()
            opts.Authority <- config.Jwt.Authority
            opts.SaveToken <- true

            if config.Jwt.Debug then
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
                    ValidAudience = config.Jwt.Audience,
                    ValidIssuer = config.Jwt.Issuer
                )
    )
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
