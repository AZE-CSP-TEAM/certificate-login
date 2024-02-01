#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443
EXPOSE 4530

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["CertAuth/CertAuth.csproj", "CertAuth/"]
COPY ["DataAccess/DataAccess.csproj", "DataAccess/"]
COPY ["Models/Models.csproj", "Models/"]
COPY ["Common/Common.csproj", "Common/"]
COPY ["SecurityManager/SecurityManager.csproj", "SecurityManager/"]
COPY ["FrdCoreCrypt/FrdCoreCrypt.csproj", "FrdCoreCrypt/"]
COPY ["Services/Services.csproj", "Services/"]
RUN dotnet restore "CertAuth/CertAuth.csproj"
COPY . .
WORKDIR "/src/CertAuth"
RUN dotnet build "CertAuth.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "CertAuth.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "CertAuth.dll"]
#ENTRYPOINT ["dotnet", "CertAuth.dll", "--urls", "http://*:5000;http://*:5001"]