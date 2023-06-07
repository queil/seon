# Seon

A configurable JWT-authenticated endpoint for running bash scripts on Linux hosts via `https` (`curl` and the like). It's parameterless and fire'n'forget i.e. you only run a POST request to configured endpoints, (each can have a different script), and get HTTP status codes back. 

## Publish

```sh
dotnet publish -r linux-x64 -c Release -p:PublishSingleFile=true --self-contained -p:PublishTrimmed=true
```
