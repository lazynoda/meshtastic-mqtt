FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy csproj and restore dependencies
COPY src/Meshtastic.Mqtt/Meshtastic.Mqtt.csproj src/Meshtastic.Mqtt/
RUN dotnet restore src/Meshtastic.Mqtt/Meshtastic.Mqtt.csproj

# Copy the rest of the code
COPY . ./
RUN dotnet publish src/Meshtastic.Mqtt/Meshtastic.Mqtt.csproj -c Release -o /app --no-restore

# Build runtime image
FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /app
COPY --from=build /app ./

EXPOSE 1883

ENTRYPOINT ["dotnet", "Meshtastic.Mqtt.dll"]
