# Seon

A configurable JWT-authenticated sub-claim-authorized endpoint for running bash scripts on Linux hosts via `https` (`curl` and the like). It's parameterless and fire'n'forget i.e. you only run a POST request to configured endpoints, (each can have a different script), and get HTTP status codes back. 

## Example usage (client)

*Assuming you have a `/deploy` endpoint configured*

```sh
curl -vvv -sS --fail-with-body -X POST -H "Authorization: Bearer $DEPLOY_TOKEN" \
      http://your.url.com/deploy
```
## Install

### Publish the project:

```sh
dotnet publish -r linux-x64 -c Release -p:PublishSingleFile=true --self-contained -p:PublishTrimmed=true
```

### Copy files to your Linux host 

(e.g. to `/opt/seon`): `seon`, `seon.pdb`, `appsettings.json`.

### Configure seon

:warning: For seon to be useful it needs to be available 

If all your endpoints use the same JWT config you can configure it on the root level but you can override 
if per endpoint, just add the `jwt` node there.

*appsettings.json*

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "System": "Debug",
      "Microsoft": "Debug"
    }
  },
  "Urls": "http://127.0.0.1:5000",
  "basePath": "",
  "seon": {
    "endpoints": {
      "/run": {
        "command": {
          "path": "/tmp/test/test.sh",
          "workingDir": "/tmp/test"
        },
        "auth": {
          "allowedSub": ""
        }
      }
    },
    "jwt": {
      "authority": "",
      "issuer": "",
      "audience": "",
      "debug": false
    }
  }
}

```

### Configure systemd

*Assuming you save it in /opt/seon/seon.service`
Example unit file:

```sh
[Unit]
Description=Script Execution Over the Network

[Service]
Type=exec
ExecStart=/opt/seon/seon
WorkingDirectory=/opt/seon
Environment=DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1

[Install]
WantedBy=multi-user.target
```

Symlink `/opt/seon/seon.service` to /etc/systemd/system/seon.service`
Reload config: `sudo systemctl daemon-reload`
Enable & start the service: `sudo systemctl enable seon.service --now`
View logs: `journalctl -u seon -xn100 | less`
