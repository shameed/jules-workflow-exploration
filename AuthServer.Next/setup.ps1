$ErrorActionPreference = "Stop"

# Create solution
dotnet new sln -n AuthServer.Next

# Add projects to solution
dotnet sln AuthServer.Next.sln add AuthServer.Main/AuthServer.Main.csproj
dotnet sln AuthServer.Next.sln add AuthServer.Migration/AuthServer.Migration.csproj

Write-Host "Solution and projects created successfully."
