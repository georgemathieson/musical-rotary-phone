# ---- Build stage -------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Restore first for better layer caching.
COPY NetworkMonitor.slnx ./
COPY src/NetworkMonitor.Shared/NetworkMonitor.Shared.csproj src/NetworkMonitor.Shared/
COPY src/NetworkMonitor.Client/NetworkMonitor.Client.csproj src/NetworkMonitor.Client/
COPY src/NetworkMonitor.Server/NetworkMonitor.Server.csproj src/NetworkMonitor.Server/
COPY tests/NetworkMonitor.Tests/NetworkMonitor.Tests.csproj tests/NetworkMonitor.Tests/
RUN dotnet restore src/NetworkMonitor.Server/NetworkMonitor.Server.csproj

COPY . .
RUN dotnet publish src/NetworkMonitor.Server/NetworkMonitor.Server.csproj -c Release -o /app

# ---- Runtime stage -----------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app ./

# Persist the SQLite database outside the image.
ENV Monitor__DatabasePath=/data/networkmonitor.db
VOLUME /data

# Dashboard. The honeypot ports are opened by the app itself (see appsettings.json);
# publish whichever ones you want reachable with -p when you run the container.
EXPOSE 8099

ENTRYPOINT ["dotnet", "NetworkMonitor.Server.dll"]
