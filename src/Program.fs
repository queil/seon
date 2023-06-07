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
    { Endpoints: Dictionary<string, SeonEndpoint>
      Jwt: JwtOptions }


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
builder.Logging.AddConsole().AddDebug() |> ignore

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
let accessDenied = setStatusCode 401

let requiresValidSub validSub : HttpHandler =
    authorizeUser (fun u -> u.HasClaim(ClaimTypes.NameIdentifier, validSub)) accessDenied

let webApp =
    choose
        [ POST
          >=> choose
              [ for KeyValue(pathPrefix, config) in seonConfig.Endpoints do
                    route pathPrefix
                    >=> requiresAuthentication (RequestErrors.UNAUTHORIZED "Bearer" $"seon{pathPrefix}" 401)
                    >=> requiresValidSub config.Auth.AllowedSub
                    >=> execute config ]

          GET
          >=> choose
              [ route "/health" >=> Successful.OK "Healthy"

                ]
          setStatusCode 404 ]

let authBuilder =
    services
        .AddAuthorization()
        .AddAuthentication()
        .AddPolicyScheme(
            JwtBearerDefaults.AuthenticationScheme,
            JwtBearerDefaults.AuthenticationScheme,
            fun opts ->

                opts.ForwardDefaultSelector <-
                    (fun ctx ->

                        let rqPath = ctx.Request.Path.ToString()

                        if seonConfig.Endpoints.ContainsKey(rqPath) then
                            $"Bearer{rqPath}"
                        else
                            "DefaultBearer")
        )

let configureJwtBearer (config: JwtOptions) =
    fun (opts: JwtBearerOptions) ->
        opts.BackchannelHttpHandler <- new Net.Http.HttpClientHandler()
        opts.Authority <- config.Authority
        opts.SaveToken <- true

        if config.Debug then
            opts.Events <-
                JwtBearerEvents(
                    OnMessageReceived =
                        fun x ->
                            task {
                                x.HttpContext
                                    .GetService<ILogger<JwtBearerEvents>>()
                                    .LogDebug("Auth header: {Token}", x.Request.Headers.Authorization)
                            }
                )

        opts.TokenValidationParameters <-
            TokenValidationParameters(
                ValidateIssuer = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidateAudience = true,
                ValidAudience = config.Audience,
                ValidIssuer = config.Issuer
            )

authBuilder.AddJwtBearer("DefaultBearer", configureJwtBearer seonConfig.Jwt)
|> ignore

for KeyValue(pathPrefix, config) in seonConfig.Endpoints do
    if obj.ReferenceEquals(config.Jwt, null) then
        ()
    else
        authBuilder.AddJwtBearer($"Bearer{pathPrefix}", configureJwtBearer config.Jwt)
        |> ignore

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
