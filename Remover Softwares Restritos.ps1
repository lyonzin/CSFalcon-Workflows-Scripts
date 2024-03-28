# ==============================================================================
# AUTOMAÇÃO DE DESINSTALAÇÃO DE SOFTWARE COM POWERSHELL
# Este script realiza a detecção e desinstalação de um software específico
# baseado no caminho do arquivo fornecido, além de limpar arquivos residuais.
# Utiliza funções avançadas como interação com a API do Windows e buscas no
# registro do sistema para localizar o software alvo.
# ==============================================================================

$Param = if ($args[0]) { $args[0] | ConvertFrom-Json }

function Get-DriveLetter ([string] $String) {
   $Definition = @’
[DllImport("kernel32.dll", SetLastError = true)]
public static extern uint QueryDosDevice(
   string lpDeviceName,
   System.Text.StringBuilder lpTargetPath,
   uint ucchMax);
'@
   $StringBuilder = New-Object System.Text.StringBuilder(65536)
   $Kernel32 = Add-Type -MemberDefinition $Definition -Name Kernel32 -Namespace Win32 -PassThru
   foreach ($Volume in (Get-WmiObject Win32_Volume | Where-Object { $_.DriveLetter })) {
       $Value = $Kernel32::QueryDosDevice($Volume.DriveLetter,$StringBuilder,65536)
       if ($Value -and $String) {
           $DevicePath = [regex]::Escape($StringBuilder.ToString())
           $String | Where-Object { $_ -match $DevicePath } | ForEach-Object {
               $String -replace $DevicePath, $Volume.DriveLetter
           }
       } elseif ($Value) {
           [PSCustomObject] @{
               DriveLetter = $Volume.DriveLetter
               DevicePath  = $StringBuilder.ToString()
           }
       }
   }
}
$Param.FilePath = Get-DriveLetter $Param.FilePath
$results = @()  # Array para armazenar resultados de diferentes etapas
:outer foreach($literalpath in "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components") {
Get-ChildItem -LiteralPath $literalpath |
 ForEach-Object {
   foreach ($valueName in $_.GetValueNames()) {
     if ($_.GetValue($valueName) -eq $Param.FilePath) {
       $ProductName=(Get-ItemProperty  -LiteralPath "HKLM:\SOFTWARE\Classes\Installer\Products\$valueName" -Name ProductName).ProductName
       foreach ($Key in (Get-ChildItem @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'))) {
           if ($Key.GetValue("DisplayName") -like "*$ProductName*") {
               $KeyFound = $Key
               break outer
           }
       }
     }
   }
 }
}
if ($KeyFound) {
 $DisplayName=(($KeyFound | Get-ItemProperty -name DisplayName -ErrorAction SilentlyContinue).DisplayName)
 $QuietUninstallString=(($KeyFound | Get-ItemProperty -name QuietUninstallString -ErrorAction SilentlyContinue).QuietUninstallString)
 $UninstallString=(($KeyFound | Get-ItemProperty -name UninstallString -ErrorAction SilentlyContinue).UninstallString)
 if ($QuietUninstall) {
   Start-Process -FilePath cmd.exe -ArgumentList "/c $($QuietUninstall)" -PassThru | Out-Null
   $results += "$DisplayName uninstall started using $($QuietUninstall)"
   $success = $true
 } else {
   if ($UninstallString -like "msiexec.exe*") {
     Start-Process -FilePath cmd.exe -ArgumentList "/c $($UninstallString.replace("/I{","/X{")) /quiet /norestart" -PassThru | Out-Null
     $results += "$DisplayName installation found, but no quiet uninstall string available. Tried with $($UninstallString.replace("/I{","/X{")) /quiet /norestart."
     $success = $true
   } else {
     $results += "$DisplayName installation found, but no quiet uninstall string available. Please consult vendor documentation."
     $success = $False
   }
 }
} else {
   $results += "Unable to find software installation."
   $success = $False
}

# Coletando Hostname, MacAddress e IP
$hostname = (Get-ComputerInfo).CsName
$macAddress = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1).MacAddress

# Inicializando variável para coletar detalhes dos arquivos residuais removidos
$residualDetails = @()

# Procura por arquivos residuais baseados em ImageFileName
$fileToFind = $Param.ImageFileName
# Definindo caminhos para excluir da busca
$excludedPaths = @('C:\Windows')
# Obtendo todos os drives do sistema exceto o C:\ para expandir a busca
$allDrives = Get-PSDrive -PSProvider 'FileSystem' | Where-Object { $_.Root -ne "C:\" }
# Incluindo o drive C:\ manualmente com exceção do caminho excluído
$searchPaths = Get-ChildItem -Path C:\ -Directory -Force | Where-Object { $excludedPaths -notcontains $_.FullName }
foreach ($drive in $allDrives) {
    $searchPaths += Get-ChildItem -Path $drive.Root -Directory -Force -ErrorAction SilentlyContinue
}
foreach ($path in $searchPaths) {
    try {
        $filePaths = Get-ChildItem -Path $path.FullName -Recurse -ErrorAction SilentlyContinue -Filter $fileToFind
        if ($filePaths.Count -gt 0) {
            foreach ($filePath in $filePaths) {
                Remove-Item $filePath.FullName -Force
                # Acumula detalhes dos arquivos residuais removidos
                $residualDetails += @{
                    Username  = $Param.Username
                    FileName  = [System.IO.Path]::GetFileName($filePath.FullName)
                    FilePath  = $filePath.FullName
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
            # Atualiza o resultado e sucesso com informações sobre a remoção de arquivos residuais
            $results += "Residual files removed."
            $success = $True
        }
    } catch {
        $results += "Error occurred during the file search."
        $success = $False
    }
}

# Preparando o objeto de retorno conforme o formato especificado, agora incluindo detalhes adicionais
# Assegurando que $details seja inicializado corretamente no início do script
if (-not $details) { $details = @() }

# Preparando o objeto de retorno para incluir múltiplos resultados
$returnObj = @{
    Results    = $results  # Utilize o array $results para armazenar os resultados de diferentes etapas
    Success    = $success
    Details    = if ($residualDetails.Count -gt 0) { $residualDetails } else { $null }
    Hostname   = $hostname
    MacAddress = $macAddress
} | ConvertTo-Json

# Emitindo o retorno em formato JSON
Write-Output $returnObj
