Clear-Host

$username = 'testUser'

$password = ConvertTo-SecureString "ditisezpz123" -AsPlainText -Force


$C = New-Object system.management.automation.pscredential ($username, $password)

$url = "https://api.github.com/user"
$token = "token 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"
$usr_agnt = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36"
$accept = "application/vnd.github.v3+json"
$header = @{"Authorization" = $token; "user-Agent" = $usr_agnt; "Accept" = $accept}

$out = Invoke-RestMethod -Method Get -Uri $url -Headers $header

Write-Output $out

function Get-AuthHeader 
{

param([System.Management.Automation.PSCredential]$Credential)
    
    if ($password -eq "TESTEN") {
        $AuthHash = @{ Username = $Credential.UserName; pswd = $Credential.Password; usr_agnt= "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36"}
        return $AuthHash
    }
    Write-Output "Wrong password"
    return $null
}

Get-AuthHeader -Credential New-Object system.management.automation.pscredential ($username, $password)

function Add-GithubCollaborator(){

[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true)]
		[String] $repoName,
		[Parameter(Mandatory=$true)]
		[String[]] $gitHubUserNames
	)
		
	if(-NOT(Token-Present))
	{
		return;
	}

	$headers = Create-GitHubHeaders
	$headers.Add("Content-Length",0)	
	
	$accountName = Get-GitHubPersonalAccountName

	foreach ($username in $gitHubUserNames)
	{
	
		$url = "https://api.github.com/repos/$accountName/$repoName/collaborators/$username"
	
		write-host "Adding $username as collaborator to repo $repoName"	
	
		Invoke-WebRequest  -Uri $url -Method PUT -Headers $headers -UseBasicParsing                                                                     
	}
}

function Add-Extension
{
    param
    (
        [string]
        
        $more_powershell_for_github,

        [string]
        $extension = "documenteren.txt"
    )
    $name = $name + "." + $extension
    $name
}
