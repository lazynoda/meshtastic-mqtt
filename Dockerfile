# syntax=docker/dockerfile:1
# Multi-arch: the .NET output is portable IL run by `dotnet`, so the SDK stage runs on the build host's
# platform. The native shim of Google RE2 (native/re2shim) is not: it is compiled in its own stage on
# the TARGET platform, against the RE2 of the same Ubuntu as the runtime image, and the runtime image
# installs the matching RE2 library from the distribution (security updates come with it). The official
# .NET images are manifest lists (amd64, arm64, arm/v7): a plain `docker build` works natively on the
# arm64 VM, and `docker buildx build --platform linux/amd64,linux/arm64 .` produces both.
ARG DOTNET_VERSION=10.0

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
WORKDIR /src

COPY global.json Meshtastic.Mqtt.sln ./
COPY src/Meshtastic.Mqtt/Meshtastic.Mqtt.csproj src/Meshtastic.Mqtt/
COPY tests/Meshtastic.Mqtt.Tests/Meshtastic.Mqtt.Tests.csproj tests/Meshtastic.Mqtt.Tests/
RUN dotnet restore Meshtastic.Mqtt.sln

COPY . ./

# The shim of RE2, for the platform of the image (no --platform: the target). The SDK image is the same
# Ubuntu as the runtime image, so the shim links against the same RE2 the runtime installs.
FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS native
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ libre2-dev \
    && rm -rf /var/lib/apt/lists/*
COPY native/re2shim/ /native/re2shim/
RUN sh /native/re2shim/build.sh /out

# `docker build --target test .` runs the test suite. The tests run on the build platform, so they get
# a shim built here, for that platform, and load the real RE2 like the broker does.
FROM build AS test
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ libre2-dev \
    && rm -rf /var/lib/apt/lists/* \
    && sh native/re2shim/build.sh /opt/re2shim
ENV LD_LIBRARY_PATH=/opt/re2shim
RUN dotnet test --solution Meshtastic.Mqtt.sln --no-restore

FROM build AS publish
RUN dotnet publish src/Meshtastic.Mqtt/Meshtastic.Mqtt.csproj -c Release --no-restore -p:UseAppHost=false -o /app

FROM mcr.microsoft.com/dotnet/runtime:${DOTNET_VERSION} AS runtime
# The runtime library of RE2 of the distribution (Ubuntu 24.04: libre2-10, the one libre2-dev of the
# native stage links against).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libre2-10 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=publish /app ./
COPY --from=native /out/libre2shim.so ./

# Non-root: the image's built-in `app` user (uid 1654). Mount the config read-only at this path.
USER $APP_UID
ENV MESHTASTIC_MQTT_CONFIG=/config/config.yaml
EXPOSE 1883

# Logs go to stdout as compact JSON. `docker run --rm -i <image> hash-password` prints a password hash.
ENTRYPOINT ["dotnet", "Meshtastic.Mqtt.dll"]
