# syntax=docker/dockerfile:1
# Multi-arch: the output is portable IL run by `dotnet`, so the SDK stage runs on the build host's
# platform and only the runtime stage is per-arch. The official .NET images are manifest lists
# (amd64, arm64, arm/v7): a plain `docker build` works natively on the arm64 VM, and
# `docker buildx build --platform linux/amd64,linux/arm64 .` produces both.
ARG DOTNET_VERSION=10.0

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
WORKDIR /src

COPY global.json Meshtastic.Mqtt.sln ./
COPY src/Meshtastic.Mqtt/Meshtastic.Mqtt.csproj src/Meshtastic.Mqtt/
COPY tests/Meshtastic.Mqtt.Tests/Meshtastic.Mqtt.Tests.csproj tests/Meshtastic.Mqtt.Tests/
RUN dotnet restore Meshtastic.Mqtt.sln

COPY . ./

# `docker build --target test .` runs the test suite.
FROM build AS test
RUN dotnet test --solution Meshtastic.Mqtt.sln --no-restore

FROM build AS publish
RUN dotnet publish src/Meshtastic.Mqtt/Meshtastic.Mqtt.csproj -c Release --no-restore -p:UseAppHost=false -o /app

FROM mcr.microsoft.com/dotnet/runtime:${DOTNET_VERSION} AS runtime
WORKDIR /app
COPY --from=publish /app ./

# Non-root: the image's built-in `app` user (uid 1654). Mount the config read-only at this path.
USER $APP_UID
ENV MESHTASTIC_MQTT_CONFIG=/config/config.yaml
EXPOSE 1883

# Logs go to stdout as compact JSON. `docker run --rm -i <image> hash-password` prints a password hash.
ENTRYPOINT ["dotnet", "Meshtastic.Mqtt.dll"]
