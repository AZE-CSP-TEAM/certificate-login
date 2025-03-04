# Base image for running the application with curl installed
FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app

# Install curl in the base image
RUN apt update && apt install -y curl

# Expose necessary ports
EXPOSE 80
EXPOSE 443
EXPOSE 4530

# Build stage: Restore dependencies and build the application
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src

# Copy project files
COPY ["CertAuth/CertAuth.csproj", "CertAuth/"]
COPY ["DataAccess/DataAccess.csproj", "DataAccess/"]
COPY ["Models/Models.csproj", "Models/"]
COPY ["Common/Common.csproj", "Common/"]
COPY ["SecurityManager/SecurityManager.csproj", "SecurityManager/"]
COPY ["FrdCoreCrypt/FrdCoreCrypt.csproj", "FrdCoreCrypt/"]
COPY ["Services/Services.csproj", "Services/"]
COPY ["CertAuth/e-imza.pfx", "CertAuth/"]

# Restore NuGet dependencies
RUN dotnet restore "CertAuth/CertAuth.csproj"

# Copy all source files
COPY . .

# Set working directory to the main project folder and build the application
WORKDIR "/src/CertAuth"
RUN dotnet build "CertAuth.csproj" -c Release -o /app/build

# Publish stage: Create a self-contained build
FROM build AS publish
RUN dotnet publish "CertAuth.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Final stage: Runtime image with curl available
FROM base AS final
WORKDIR /app

# Copy the published files to the runtime image
COPY --from=publish /app/publish .

# Ensure the .pfx file is available in the runtime image
COPY ["CertAuth/e-imza.pfx", "/app/e-imza.pfx"]

# Define the entry point for the application
ENTRYPOINT ["dotnet", "CertAuth.dll"]
