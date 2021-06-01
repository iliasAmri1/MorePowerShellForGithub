#TYPE Microsoft.PowerShell.Commands.HistoryInfo
"Id","CommandLine","ExecutionStatus","StartExecutionTime","EndExecutionTime"
"1","Get-GitHubUser -Current","Failed","01/06/2021 13:29:40","01/06/2021 13:29:44"
"2","Set-GitHubProfile -Company 'AP Hogeschool'","Failed","01/06/2021 13:29:47","01/06/2021 13:29:48"
"3","$repo = New-GitHubRepository `
-RepositoryName test-from-pwsh","Failed","01/06/2021 13:29:52","01/06/2021 13:29:53"
"4","clear","Completed","01/06/2021 13:30:09","01/06/2021 13:30:09"
"5","cd .ssh","Completed","01/06/2021 13:30:19","01/06/2021 13:30:19"
"6","cd C:\Users\Windows\.ssh","Completed","01/06/2021 13:32:25","01/06/2021 13:32:25"
"7","clear","Completed","01/06/2021 13:32:38","01/06/2021 13:32:38"
"8","? Read-Host -AsSecureString -Prompt ?token? |
ConvertFrom-SecureString |
Tee-Object .\secret.txt |
ConvertTo-SecureString |
Set-Variable ss_token","Completed","01/06/2021 13:33:05","01/06/2021 13:33:05"
"9","Read-Host -AsSecureString -Prompt ?token? |
ConvertFrom-SecureString |
Tee-Object .\secret.txt |
ConvertTo-SecureString |
Set-Variable ss_token","Stopped","01/06/2021 13:33:09","01/06/2021 13:33:13"
"10","Read-Host -AsSecureString -Prompt ?token? |
ConvertFrom-SecureString |
Tee-Object .\secret.txt |
ConvertTo-SecureString |
Set-Variable ss_token","Stopped","01/06/2021 13:33:20","01/06/2021 13:33:22"
"11","$creds = New-Object pscredential 'user?, $ss_token","Completed","01/06/2021 13:33:52","01/06/2021 13:33:52"
"12","Get-GitHubUser -Current","Failed","01/06/2021 13:33:59","01/06/2021 13:34:00"
"13","clear","Completed","01/06/2021 13:34:11","01/06/2021 13:34:11"
"14","Get-GitHubUser -Current.
Set-GitHubProfile -Company 'AP Hogeschool'
? $repo = New-GitHubRepository `-RepositoryName test-from-pwsh","Failed","01/06/2021 13:34:49","01/06/2021 13:34:51"
"15","Get-GitHubUser -Current.
Set-GitHubProfile -Company 'AP Hogeschool'
? $repo = New-GitHubRepository -RepositoryName test-from-pwsh","Failed","01/06/2021 13:34:57","01/06/2021 13:34:58"
"16","Get-GitHubUser -Current.
Set-GitHubProfile -Company 'AP Hogeschool'
? $repo = New-GitHubRepository -RepositoryName test-from-pwsh","Failed","01/06/2021 13:34:58","01/06/2021 13:34:59"
"17","Get-GitHubUser -Current.
Set-GitHubProfile -Company 'AP Hogeschool'
? $repo = New-GitHubRepository -RepositoryName test-from-pwsh","Failed","01/06/2021 13:35:02","01/06/2021 13:35:03"
"18","clear","Completed","01/06/2021 13:35:18","01/06/2021 13:35:18"
"19","Get-GitHubUser -Current.
Set-GitHubProfile -Company 'AP Hogeschool'
? $repo = New-GitHubRepository -RepositoryName test-from-pwsh","Failed","01/06/2021 13:35:24","01/06/2021 13:35:25"
"20","clear","Completed","01/06/2021 13:39:26","01/06/2021 13:39:26"
"21","Get-GitHubUser -Current.
Set-GitHubProfile -Company 'AP Hogeschool'
? $repo = New-GitHubRepository -RepositoryName test-from-pwsh","Failed","01/06/2021 13:39:44","01/06/2021 13:39:45"
"22","Read-Host -AsSecureString -Prompt ?token? |
ConvertFrom-SecureString |
Tee-Object .\secret.txt |
ConvertTo-SecureString |
Set-Variable ss_token","Completed","01/06/2021 13:40:52","01/06/2021 13:40:54"
"23","Read-Host -AsSecureString -Prompt ?token? |
ConvertFrom-SecureString |
Tee-Object .\secret.txt |
ConvertTo-SecureString |
Set-Variable ss_token","Completed","01/06/2021 13:40:57","01/06/2021 13:41:06"
"24","$creds = New-Object pscredential 'user?, $ss_token","Completed","01/06/2021 13:41:21","01/06/2021 13:41:21"
"25","$creds = New-Object pscredential 'user?, $ss_token
Set-GitHubAuthentication -SessionOnly ` -Credential $creds","Completed","01/06/2021 13:41:40","01/06/2021 13:41:40"
"26","Get-GitHubUser -Current","Completed","01/06/2021 13:42:04","01/06/2021 13:42:05"
"27","Set-GitHubProfile -Company 'AP Hogeschool'","Completed","01/06/2021 13:42:16","01/06/2021 13:42:17"
"28","$repo = New-GitHubRepository `
-RepositoryName test-from-pwsh","Completed","01/06/2021 13:42:29","01/06/2021 13:42:31"
"29","Get-Help Invoke-RestMethod","Completed","01/06/2021 13:43:48","01/06/2021 13:43:49"
"30","Get-Help Invoke-RestMethod","Completed","01/06/2021 13:43:52","01/06/2021 13:43:52"
"31","Get-Help Invoke-RestMethod","Completed","01/06/2021 13:43:53","01/06/2021 13:43:53"
"32","Read-Host -AsSecureString -Prompt ?token? |
ConvertFrom-SecureString |
Tee-Object .\secret.txt |
ConvertTo-SecureString |
Set-Variable ss_tokenclear","Stopped","01/06/2021 13:43:55","01/06/2021 13:43:56"
"33","clear","Completed","01/06/2021 13:43:58","01/06/2021 13:43:58"
"34","Get-Help Invoke-RestMethod","Completed","01/06/2021 13:44:00","01/06/2021 13:44:00"
"35","Invoke-RestMethod -Headers $headers
https://api.github.com","Stopped","01/06/2021 13:44:25","01/06/2021 13:44:51"
"36"," Invoke-RestMethod -Headers $headers","Stopped","01/06/2021 13:44:52","01/06/2021 13:45:26"
"37"," Invoke-RestMethod -Headers $headers","Completed","01/06/2021 13:45:27","01/06/2021 13:45:44"
"38","$auth = `
[System.Convert]::ToBase64String([char[]]$creds.GetNet
workCredential().Password)","Failed","01/06/2021 13:45:56","01/06/2021 13:45:56"
"39","$auth = `
[System.Convert]::ToBase64String([char[]]$creds.GetNetworkCredential().Password)","Completed","01/06/2021 13:46:22","01/06/2021 13:46:22"
"40","$auth = `
[System.Convert]::ToBase64String([char[]]$creds.GetNetworkCredential().Password)$headers = @{Authorization=""Basic $auth""}","Completed","01/06/2021 13:46:32","01/06/2021 13:46:32"
"41","Invoke-RestMethod -Headers $headers `
https://api.github.com/user","Completed","01/06/2021 13:46:48","01/06/2021 13:46:49"
"42","$api = 'https://api.github.com?","Completed","01/06/2021 13:47:07","01/06/2021 13:47:07"
"43","$api","Completed","01/06/2021 13:47:15","01/06/2021 13:47:15"
"44","Invoke-RestMethod -Headers $headers $api/user
#(https://docs.github.com/en/rest/reference/users#getthe-authenticated-user)","Completed","01/06/2021 13:47:26","01/06/2021 13:47:26"
"45","Invoke-RestMethod -Headers $headers $api/user/keys
#(https://docs.github.com/en/rest/reference/users#list
-public-ssh-keys-for-the-authenticated-user)","Failed","01/06/2021 13:47:36","01/06/2021 13:47:36"
"46","Invoke-RestMethod -Headers $headers $api/user/keys
#(https://docs.github.com/en/rest/reference/users#list
-public-ssh-keys-for-the-authenticated-user)","Failed","01/06/2021 13:47:39","01/06/2021 13:47:39"
"47","Invoke-RestMethod -Headers $headers $api/user/keys
#(https://docs.github.com/en/rest/reference/users#list-public-ssh-keys-for-the-authenticated-user)","Completed","01/06/2021 13:47:52","01/06/2021 13:47:52"
"48","Read-Host -AsSecureString -Prompt ?token? |
ConvertFrom-SecureString |
Tee-Object .\secret.txt |
ConvertTo-SecureString |
Set-Variable ss_tokenclear","Completed","01/06/2021 16:00:21","01/06/2021 16:00:21"
"49","$api","Completed","01/06/2021 16:01:21","01/06/2021 16:01:21"
"50","Invoke-RestMethod -Headers $headers $api/user
#(https://docs.github.com/en/rest/reference/users#getthe-authenticated-user)","Completed","01/06/2021 16:01:33","01/06/2021 16:01:34"
"51","Invoke-RestMethod -Headers $headers $api/user/keys
#(https://docs.github.com/en/rest/reference/users#list
-public-ssh-keys-for-the-authenticated-user)","Failed","01/06/2021 16:01:40","01/06/2021 16:01:40"
"52","Invoke-RestMethod -Headers $headers $api/user/keys
","Completed","01/06/2021 16:01:53","01/06/2021 16:01:53"
"53","Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body @{company='AP Hogeschool - Antwerpen?}
","Completed","01/06/2021 16:03:20","01/06/2021 16:03:21"
"54","? Invoke-RestMethod -Headers $headers `-Method Patch $api/user `
-Body @{company='AP Hogeschool - Antwerpen?}","Completed","01/06/2021 16:03:54","01/06/2021 16:03:54"
"55"," Invoke-RestMethod -Headers $headers `-Method Patch $api/user `
-Body @{company='AP Hogeschool - Antwerpen?}","Completed","01/06/2021 16:04:03","01/06/2021 16:04:03"
"56","Invoke-RestMethod -Headers $headers `
-Method Patch $api/user","Completed","01/06/2021 16:04:35","01/06/2021 16:04:35"
"57","Invoke-RestMethod -Headers $headers -Body @{company='AP Hogeschool - Antwerpen?}","Stopped","01/06/2021 16:05:09","01/06/2021 16:08:16"
"58","? Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body @{company='AP Hogeschool - Antwerpen?}","Completed","01/06/2021 16:08:20","01/06/2021 16:08:20"
"59","? Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body @{company='AP Hogeschool - Antwerpen?}","Completed","01/06/2021 16:08:23","01/06/2021 16:08:23"
"60","? Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body @{company='AP Hogeschool - Antwerpen?}","Completed","01/06/2021 16:08:24","01/06/2021 16:08:24"
"61","? Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body @{company='AP Hogeschool - Antwerpen?}","Completed","01/06/2021 16:08:25","01/06/2021 16:08:25"
"62","? Invoke-RestMethod -Headers $headers -Method Patch $api/user-Body @{company='AP Hogeschool - Antwerpen?}","Completed","01/06/2021 16:08:40","01/06/2021 16:08:40"
"63","? Invoke-RestMethod -Headers $headers -Method Patch $api/user","Completed","01/06/2021 16:08:49","01/06/2021 16:08:49"
"64","clear","Completed","01/06/2021 16:09:40","01/06/2021 16:09:40"
"65","Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body @{""company='AP Hogeschool - Antwerpen""}
#(https://docs.github.com/en/rest/reference/users#upda
te-the-authenticated-user)","Failed","01/06/2021 16:10:46","01/06/2021 16:10:46"
"66","Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body @{company='AP Hogeschool - Antwerpen?}
","Completed","01/06/2021 16:16:50","01/06/2021 16:16:50"
"67","clear","Completed","01/06/2021 16:16:52","01/06/2021 16:16:52"
"68","Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body @{company='AP Hogeschool - Antwerpen?}
","Completed","01/06/2021 16:16:55","01/06/2021 16:16:55"
"69","Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body @{company='AP Hogeschool - Antwerpen?}
","Completed","01/06/2021 16:16:58","01/06/2021 16:16:59"
"70","clear","Completed","01/06/2021 16:17:03","01/06/2021 16:17:03"
"71","Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body (company='AP Hogeschool - Antwerpen?}
","Failed","01/06/2021 16:17:21","01/06/2021 16:17:21"
"72","Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body (company='AP Hogeschool - Antwerpen?
","Failed","01/06/2021 16:17:30","01/06/2021 16:17:30"
"73","clear","Completed","01/06/2021 16:17:34","01/06/2021 16:17:34"
"74","Invoke-RestMethod -Headers $headers ` -Method Patch $api/user ` -Body @{company='AP Hogeschool - Antwerpen?}
","Completed","01/06/2021 16:18:16","01/06/2021 16:18:16"
"75","Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body @{company='AP Hogeschool - Antwerpen?}
","Completed","01/06/2021 16:20:03","01/06/2021 16:20:04"
"76","clear","Completed","01/06/2021 16:20:08","01/06/2021 16:20:08"
"77","Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body {company='AP Hogeschool - Antwerpen?}
","Completed","01/06/2021 16:20:37","01/06/2021 16:20:38"
"78","clear","Completed","01/06/2021 16:20:45","01/06/2021 16:20:45"
"79","Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body ""company"":'AP Hogeschool - Antwerpen?
","Completed","01/06/2021 16:21:30","01/06/2021 16:21:30"
"80","clear","Completed","01/06/2021 16:21:44","01/06/2021 16:21:44"
"81","clear","Completed","01/06/2021 16:30:12","01/06/2021 16:30:12"
"82","for (($i=1), ($repos=@()), ($res=$null); ($i -eq 1) -or ($res.Count); $i++) {
Write-Host $i
$res = Invoke-RestMethod -Headers $headers $api/user/repos?page=$i
$repos += $res
}
$repos.ssh_url","Completed","01/06/2021 16:32:29","01/06/2021 16:32:30"
"83","Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body ""company"":'AP Hogeschool - Antwerpen?
Invoke-RestMethod -Headers $headers `
-Method Patch $api/user `
-Body ""company"":""AP Hogeschool - Antwerpen"" ","Completed","01/06/2021 16:32:41","01/06/2021 16:32:41"
"84","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D1","Completed","01/06/2021 16:32:43","01/06/2021 16:32:45"
"85","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object 
git clone $_.ssh_url $_.owner.login
$u =
Where-Object -Property Group -EQ G_1SNB_D1","Stopped","01/06/2021 16:33:14","01/06/2021 16:33:17"
"86","clear","Completed","01/06/2021 16:33:19","01/06/2021 16:33:19"
"87","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D1","Completed","01/06/2021 16:33:21","01/06/2021 16:33:21"
"88","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D4
","Completed","01/06/2021 16:33:55","01/06/2021 16:33:56"
"89","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D3
","Completed","01/06/2021 16:34:00","01/06/2021 16:34:00"
"90","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D2
","Completed","01/06/2021 16:34:04","01/06/2021 16:34:05"
"91","1clear","Completed","01/06/2021 16:34:07","01/06/2021 16:34:07"
"92","clear","Completed","01/06/2021 16:34:09","01/06/2021 16:34:09"
"93","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D4
","Completed","01/06/2021 16:34:15","01/06/2021 16:34:15"
"94","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D1
","Completed","01/06/2021 16:34:20","01/06/2021 16:34:20"
"95","clear","Completed","01/06/2021 16:34:25","01/06/2021 16:34:25"
"96","for (($i=1), ($repos=@()), ($res=$null); ($i -eq 1) -or ($res.Count); $i++) {
Write-Host $i
$res = Invoke-RestMethod -Headers $headers $api/user/repos?page=$i
$repos += $res
}
$repos.ssh_url","Completed","01/06/2021 16:34:42","01/06/2021 16:34:42"
"97","for (($i=1), ($repos=@()), ($res=$null); ($i -eq 1) -or ($res.Count); $i++) {
Write-Host $i
$res = Invoke-RestMethod -Headers $headers $api/user/repos?page=$i
$repos += $res
}
$repos.ssh_url
$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D1","Completed","01/06/2021 16:34:57","01/06/2021 16:34:58"
"98","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D1","Completed","01/06/2021 16:35:06","01/06/2021 16:35:07"
"99","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D1","Completed","01/06/2021 16:35:08","01/06/2021 16:35:08"
"100","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D1","Completed","01/06/2021 16:35:23","01/06/2021 16:35:23"
"101","clear","Completed","01/06/2021 16:35:25","01/06/2021 16:35:25"
"102","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D1","Completed","01/06/2021 16:35:28","01/06/2021 16:35:29"
"103","clear","Completed","01/06/2021 16:56:15","01/06/2021 16:56:15"
"104","Read-Host -AsSecureString","Completed","01/06/2021 16:56:24","01/06/2021 16:56:28"
"105","$creds","Completed","01/06/2021 17:10:14","01/06/2021 17:10:14"
"106","$repos | Where-Object -Property Name -EQ 'PS-misc' |
ForEach-Object {
git clone $_.ssh_url $_.owner.login
$u = Invoke-RestMethod -Headers $headers $_.owner.url
[PSCustomObject]@{Owner=$u.login; Name=$u.name; Group=$u.bio}
} |
Tee-Object -Variable owners |
Export-Csv -Path repos.csv -Encoding UTF8
Import-Csv -Path .\repos.csv |
Where-Object -Property Group -EQ G_1SNB_D1","Completed","01/06/2021 17:11:00","01/06/2021 17:11:00"
"107","Set-GithubAuthentication -Credential $creds -SessionOnly","Completed","01/06/2021 17:11:23","01/06/2021 17:11:23"
"108","CLEAR","Completed","01/06/2021 17:11:28","01/06/2021 17:11:28"
"109","Set-GithubAuthentication -Credential $creds -SessionOnly","Completed","01/06/2021 17:11:31","01/06/2021 17:11:31"
"110","Get-Command -Module PowerShellForGitHub -Name *auth*","Completed","01/06/2021 17:12:17","01/06/2021 17:12:17"
"111","Test-GitHubAuthenticationConfigured     ","Completed","01/06/2021 17:12:43","01/06/2021 17:12:43"
"112","git config -l | grep user.name","Completed","01/06/2021 17:17:00","01/06/2021 17:17:00"
"113","git config -l | grep user.email
","Completed","01/06/2021 17:17:07","01/06/2021 17:17:07"
"114","ssh -T git@github.com","Completed","01/06/2021 17:17:15","01/06/2021 17:17:16"
"115","clear","Completed","01/06/2021 17:17:20","01/06/2021 17:17:20"
"116","-T git@github.com","Completed","01/06/2021 17:17:34","01/06/2021 17:17:34"
"117","Get-AzADUser -UserPrincipalName (Get-AzContext).Account","Completed","01/06/2021 17:18:19","01/06/2021 17:18:19"
"118","(Get-AzADUser -UserPrincipalName (Get-AzContext).Account)","Completed","01/06/2021 17:18:26","01/06/2021 17:18:26"
"119","clear","Completed","01/06/2021 17:18:30","01/06/2021 17:18:30"
"120","git config user name","Completed","01/06/2021 17:18:48","01/06/2021 17:18:48"
"121","git config user name","Completed","01/06/2021 17:18:50","01/06/2021 17:18:50"
"122","git config user.ame","Completed","01/06/2021 17:19:01","01/06/2021 17:19:01"
"123","git config user.name","Completed","01/06/2021 17:19:07","01/06/2021 17:19:07"
"124","clear","Completed","01/06/2021 17:26:46","01/06/2021 17:26:46"
"125","git clone https://github.com/iliasAmri1/MorePowerShellForGithub.git","Completed","01/06/2021 17:28:26","01/06/2021 17:28:30"
"126","clear","Completed","01/06/2021 17:28:59","01/06/2021 17:28:59"
"127","ls","Completed","01/06/2021 17:29:08","01/06/2021 17:29:08"
"128","git clone https://github.com/iliasAmri1/MorePowerShellForGithub.git","Completed","01/06/2021 17:29:19","01/06/2021 17:29:24"
"129","ls","Completed","01/06/2021 17:29:31","01/06/2021 17:29:31"
"130","clear","Completed","01/06/2021 17:29:34","01/06/2021 17:29:34"
"131","git clone https://github.com/iliasAmri1/MorePowerShellForGithub.git","Completed","01/06/2021 17:29:42","01/06/2021 17:29:56"
"132","ls","Completed","01/06/2021 17:29:58","01/06/2021 17:29:58"
"133","git clone https://github.com/iliasAmri1/MorePowerShellForGithub.git","Completed","01/06/2021 17:30:02","01/06/2021 17:30:23"
"134","git clone https://github.com/iliasAmri1/MorePowerShellForGithub.git","Completed","01/06/2021 17:30:26","01/06/2021 17:30:45"
"135","celar","Completed","01/06/2021 17:30:57","01/06/2021 17:30:57"
"136","clear","Completed","01/06/2021 17:30:58","01/06/2021 17:30:58"
"137","git clone https://github.com/iliasAmri1/MorePowerShellForGithub.git","Completed","01/06/2021 17:31:15","01/06/2021 17:31:31"
"138","ls","Completed","01/06/2021 17:31:52","01/06/2021 17:31:52"
"139","git clone https://github.com/iliasAmri1/MorePowerShellForGithub.git","Completed","01/06/2021 17:32:51","01/06/2021 17:36:16"
"140","cd","Completed","01/06/2021 17:36:40","01/06/2021 17:36:40"
"141","cd ..","Completed","01/06/2021 17:36:43","01/06/2021 17:36:43"
"142","git clone https://github.com/iliasAmri1/MorePowerShellForGithub.git","Completed","01/06/2021 17:36:49","01/06/2021 17:37:04"
"143","cd .ssh","Completed","01/06/2021 17:37:24","01/06/2021 17:37:24"
"144","ls","Completed","01/06/2021 17:37:28","01/06/2021 17:37:28"
"145","git clone git@github.com:iliasAmri1/MorePowerShellForGithub.git","Completed","01/06/2021 17:37:46","01/06/2021 17:37:47"
"146","Get-History ","Completed","01/06/2021 17:39:12","01/06/2021 17:39:12"
"147","Get-help","Completed","01/06/2021 17:39:22","01/06/2021 17:39:22"
"148","Get-help Get-History","Completed","01/06/2021 17:39:31","01/06/2021 17:39:31"
"149","Get-History | Export-ps1 snippets.ps1","Completed","01/06/2021 17:40:51","01/06/2021 17:40:51"
"150","Get-Member | Get-History","Completed","01/06/2021 17:41:08","01/06/2021 17:41:08"
"151","Get-help","Completed","01/06/2021 17:41:15","01/06/2021 17:41:15"
"152","Get-help | Get-History","Completed","01/06/2021 17:41:21","01/06/2021 17:41:21"
"153","clear","Completed","01/06/2021 17:41:24","01/06/2021 17:41:24"
"154","Get-History | Export-CSV snippets.ps1","Completed","01/06/2021 17:46:27","01/06/2021 17:46:27"
"155","clear","Completed","01/06/2021 17:49:21","01/06/2021 17:49:21"
"156","cd MorePowerShellForGitHub","Completed","01/06/2021 17:52:31","01/06/2021 17:52:31"
"157","git init","Completed","01/06/2021 17:53:05","01/06/2021 17:53:05"
"158","git remote add origin $repo.ssh_url","Completed","01/06/2021 17:53:59","01/06/2021 17:53:59"
"159","$repo","Completed","01/06/2021 17:54:08","01/06/2021 17:54:08"
"160","$repo = New-GitHubRepository `
-RepositoryName MorePowerShellForGithub","Failed","01/06/2021 17:55:20","01/06/2021 17:55:22"
"161","cd ..","Completed","01/06/2021 17:55:37","01/06/2021 17:55:37"
"162","$repo = New-GitHubRepository `
-RepositoryName MorePowerShellForGithub","Failed","01/06/2021 17:55:40","01/06/2021 17:55:41"
"163","cd MorePowerShellForGitHub","Completed","01/06/2021 17:55:48","01/06/2021 17:55:48"
"164","$repo","Completed","01/06/2021 17:57:55","01/06/2021 17:57:55"
"165","$repo = New-GitHubRepository `
-RepositoryName MorePowerShellForGithub","Failed","01/06/2021 17:58:26","01/06/2021 17:58:27"
"166","$repo = New-GitHubRepository `
-RepositoryName MorePowerShellForGithub `
","Failed","01/06/2021 17:59:14","01/06/2021 17:59:15"
"167","cd","Completed","01/06/2021 17:59:40","01/06/2021 17:59:40"
"168","cd ..","Completed","01/06/2021 17:59:42","01/06/2021 17:59:42"
"169","cd MorePowerShellForGitHub","Completed","01/06/2021 17:59:51","01/06/2021 17:59:51"
"170","cd ..","Completed","01/06/2021 18:00:22","01/06/2021 18:00:22"
"171","Remove-Variable $repo","Completed","01/06/2021 18:00:33","01/06/2021 18:00:33"
"172","$repo = New-GitHubRepository `
-RepositoryName MorePowerShellForGithub 
","Failed","01/06/2021 18:00:46","01/06/2021 18:00:47"
"173","Get-GitHubUser -Current
? Set-GitHubProfile -Company 'AP Hogeschool'

$repo = New-GitHubRepository `
-RepositoryName MorePowerShellForGithub 
","Failed","01/06/2021 18:01:53","01/06/2021 18:01:55"
"174","Get-GitHubUser -Current
Set-GitHubProfile -Company 'AP Hogeschool'

$repo = New-GitHubRepository `
-RepositoryName MorePowerShellForGithub 
","Failed","01/06/2021 18:02:06","01/06/2021 18:02:10"
"175","clear","Completed","01/06/2021 19:45:53","01/06/2021 19:45:53"
"176","git remote add origin $repo.ssh_url","Completed","01/06/2021 19:47:38","01/06/2021 19:47:38"
"177","clear","Completed","01/06/2021 19:47:39","01/06/2021 19:47:39"
"178","$repo = New-GitHubRepository `
-RepositoryName MorePowerShellForGithub ","Failed","01/06/2021 19:49:33","01/06/2021 19:49:34"
"179","clear","Completed","01/06/2021 19:51:36","01/06/2021 19:51:36"
"180","$repo = New-GitHubRepository `
-RepositoryName MorePowerShellForGithub ","Completed","01/06/2021 19:53:07","01/06/2021 19:53:10"
"181","ls","Completed","01/06/2021 19:53:13","01/06/2021 19:53:13"
"182","git remote add origin $repo.ssh_url","Completed","01/06/2021 19:54:18","01/06/2021 19:54:18"
"183","cd MorePowerShellForGithub","Completed","01/06/2021 19:54:39","01/06/2021 19:54:39"
"184","git remote add origin $repo.ssh_url","Completed","01/06/2021 19:54:43","01/06/2021 19:54:43"
"185","push -u origin main","Completed","01/06/2021 19:56:03","01/06/2021 19:56:03"
"186","push -u origin main","Completed","01/06/2021 19:56:07","01/06/2021 19:56:07"
"187","clear","Completed","01/06/2021 19:56:09","01/06/2021 19:56:09"
"188","git push -u origin main","Completed","01/06/2021 19:56:11","01/06/2021 19:56:14"
"189","clear","Completed","01/06/2021 19:56:17","01/06/2021 19:56:17"
"190","git push -u origin main","Completed","01/06/2021 19:56:22","01/06/2021 19:56:23"
"191","clear","Completed","01/06/2021 19:56:35","01/06/2021 19:56:35"
"192","Get-History | Export-CSV snippets.ps1","Completed","01/06/2021 19:57:04","01/06/2021 19:57:04"
"193","ls?","Completed","01/06/2021 19:58:27","01/06/2021 19:58:27"
"194","ls","Completed","01/06/2021 19:58:28","01/06/2021 19:58:28"
"195","clear","Completed","01/06/2021 19:58:48","01/06/2021 19:58:48"
"196","gitinit","Completed","01/06/2021 19:58:59","01/06/2021 19:58:59"
"197","git init","Completed","01/06/2021 19:59:01","01/06/2021 19:59:01"
"198","clear","Completed","01/06/2021 19:59:14","01/06/2021 19:59:14"
"199","git add comit","Completed","01/06/2021 19:59:46","01/06/2021 19:59:47"
"200","git commit","Completed","01/06/2021 19:59:50","01/06/2021 19:59:50"
"201","git add .","Completed","01/06/2021 20:00:00","01/06/2021 20:00:00"
"202","git commit","Completed","01/06/2021 20:00:02","01/06/2021 20:00:15"
"203","git add .","Completed","01/06/2021 20:01:00","01/06/2021 20:01:00"
"204","git add .","Completed","01/06/2021 20:01:01","01/06/2021 20:01:01"
"205","git commit","Completed","01/06/2021 20:01:02","01/06/2021 20:02:46"
"206","git push -u origin main","Completed","01/06/2021 20:02:55","01/06/2021 20:03:00"
"207","git push -u origin main","Completed","01/06/2021 20:03:36","01/06/2021 20:03:37"
"208","$auth = `
[System.Convert]::ToBase64String([char[]]$creds.GetNet
workCredential().Password)
$headers = @{Authorization=""Basic $auth""}","Failed","01/06/2021 20:56:16","01/06/2021 20:56:16"
"209","$auth = `
[System.Convert]::ToBase64String([char[]]$creds.GetNet
workCredential().Password)
$headers = @{Authorization=""Basic $auth""}","Failed","01/06/2021 20:56:17","01/06/2021 20:56:17"
"210","$auth = `
[System.Convert]::ToBase64String([char[]]$creds.GetNet
workCredential().Password)
$headers = @{Authorization=""Basic $auth""}","Failed","01/06/2021 20:56:18","01/06/2021 20:56:18"
"211","$auth = `
[System.Convert]::ToBase64String([char[]]$creds.GetNet
workCredential().Password)
$headers = @{Authorization=""Basic $auth""}","Failed","01/06/2021 20:56:19","01/06/2021 20:56:19"
"212","$auth = `
[System.Convert]::ToBase64String([char[]]$creds.GetNet
workCredential().Password)
$headers = @{Authorization=""Basic $auth""}","Failed","01/06/2021 20:56:20","01/06/2021 20:56:20"
"213","clear","Completed","01/06/2021 20:56:26","01/06/2021 20:56:26"
"214","$auth = `
[System.Convert]::ToBase64String([char[]]$creds.GetNet
workCredential().Password)","Failed","01/06/2021 21:38:55","01/06/2021 21:38:55"
"215","clear","Completed","01/06/2021 21:43:44","01/06/2021 21:43:44"
"216","$auth = [System.Convert]::ToBase64String([char[]]$creds.GetNet
workCredential().Password)","Failed","01/06/2021 21:43:57","01/06/2021 21:43:57"
"217","cls","Completed","01/06/2021 21:44:00","01/06/2021 21:44:00"
"218","cls","Completed","01/06/2021 21:44:05","01/06/2021 21:44:05"
"219","clr","Completed","01/06/2021 21:44:06","01/06/2021 21:44:06"
"220","cls","Completed","01/06/2021 21:44:07","01/06/2021 21:44:07"
"221","Read-Host -AsSecureString -Prompt ?token? |
ConvertFrom-SecureString |
Tee-Object .\secret.txt |
ConvertTo-SecureString |
Set-Variable ss_token","Completed","01/06/2021 21:44:37","01/06/2021 21:44:45"
"222","$auth = `
[System.Convert]::ToBase64String([char[]]$creds.GetNet
workCredential().Password)","Failed","01/06/2021 21:45:22","01/06/2021 21:45:22"
"223","CLS","Completed","01/06/2021 21:45:24","01/06/2021 21:45:24"
"224","$auth = `
[System.Convert]::ToBase64String([char[]]$creds.GetNetworkCredential().Password)","Completed","01/06/2021 21:45:50","01/06/2021 21:45:50"
"225","$headers = @{Authorization=""Basic $auth""}","Completed","01/06/2021 21:46:00","01/06/2021 21:46:00"
"226","https://api.github.com/user","Completed","01/06/2021 21:46:09","01/06/2021 21:46:09"
"227","CLEAR","Completed","01/06/2021 21:46:23","01/06/2021 21:46:23"
"228","Invoke-RestMethod -Headers $headers `
https://api.github.com/user","Completed","01/06/2021 21:47:13","01/06/2021 21:47:14"
"229","get /user/kegs","Completed","01/06/2021 21:54:57","01/06/2021 21:54:57"
"230","clear","Completed","01/06/2021 21:55:00","01/06/2021 21:55:00"
"231","clear","Completed","01/06/2021 21:55:13","01/06/2021 21:55:13"
"232","cd C:\Users\Windows\.ssh","Completed","01/06/2021 21:57:22","01/06/2021 21:57:22"
"233","ls","Completed","01/06/2021 21:57:25","01/06/2021 21:57:25"
"234","cat ~/.sh","Completed","01/06/2021 21:58:09","01/06/2021 21:58:10"
"235","cat ~/.shh/id_rsa.pub","Completed","01/06/2021 21:58:18","01/06/2021 21:58:18"
"236","clear","Completed","01/06/2021 21:58:20","01/06/2021 21:58:20"
"237","clear","Completed","01/06/2021 21:58:21","01/06/2021 21:58:21"
"238","cat ~/.shh/id_rsa.pub","Completed","01/06/2021 21:58:24","01/06/2021 21:58:24"
"239","cat C:\Users\Windows\.ssh\id_rsa.pub","Completed","01/06/2021 21:58:54","01/06/2021 21:58:54"
"240","git commit","Completed","01/06/2021 22:00:37","01/06/2021 22:00:37"
"241","git add .","Completed","01/06/2021 22:00:45","01/06/2021 22:00:45"
"242","git commit ","Completed","01/06/2021 22:01:00","01/06/2021 22:01:00"
"243","clear","Completed","01/06/2021 22:01:03","01/06/2021 22:01:03"
"244","cd C:\Users\Windows\.ssh\MorePowerShellForGithub","Completed","01/06/2021 22:01:39","01/06/2021 22:01:39"
"245","git add .","Completed","01/06/2021 22:01:50","01/06/2021 22:01:50"
"246","git commit","Completed","01/06/2021 22:01:53","01/06/2021 22:02:30"
"247","git push","Completed","01/06/2021 22:02:33","01/06/2021 22:02:35"
"248","git push -u origin main","Completed","01/06/2021 22:02:45","01/06/2021 22:02:46"
"249","Invoke-RestMethod -Headers $headers  -Body ' {""company"" =""AP Hogeschool - Antwerpen""} ' -Method Patch","Completed","01/06/2021 22:10:03","01/06/2021 22:10:33"
"250","Invoke-RestMethod -Headers $headers -Uri https://api.github.com/user -Body '{""company"": ""AP Hogeschool - Antwerpen""}' -Method Patch","Completed","01/06/2021 22:11:09","01/06/2021 22:11:10"
"251","clear","Completed","01/06/2021 22:11:12","01/06/2021 22:11:12"
"252","git add .","Completed","01/06/2021 22:11:15","01/06/2021 22:11:15"
