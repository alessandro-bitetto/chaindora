FROM mcr.microsoft.com/dotnet/sdk:9.0@sha256:01fabc4758d1d74e39eda700c8463dae6241a61481f973683692ddcb59a5eeb7
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
RUN dotnet tool install Paket --version 10.3.1 --tool-path /opt/paket
ENV PATH="/opt/paket:${PATH}"
