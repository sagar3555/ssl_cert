param($CSRName)
Import-Module PSPKI
Write-Host $CSRName
#$CSRName = "test-ihe-rapport20180201.csr"
echo $CSRName
$source_path = "E:\4-FlaskForms\key and csr\"
$destination_path = "E:\4-FlaskForms\Certificate\"
$CSRFile = Get-ChildItem -Path $source_path -File | Where-Object {$_.Name -eq $CSRName}
$cert_Name = $CSRFile.BaseName
$CAConfig = "SEZVM3705P.ica.ia-hc.net\Issuing CA Device v3"
$CAServer = "SEZVM3705P.ica.ia-hc.net"
$LogPath = "E:\cert_auto\Logs\"
$Request = Certreq -Submit -config $CAConfig -attrib "CertificateTemplate:ICAV3WebServer" "$source_path$CSRName"
$RequestString = $Request | Select-String -Pattern "RequestId" | select -First 1
$RequestId = ($RequestString -replace "RequestId:").Trim()
$ApprovalStatus = Get-PendingRequest -CertificationAuthority $CAServer -RequestID $RequestId | Approve-CertificateRequest
$Cert = Get-IssuedRequest -CertificationAuthority $CAServer -RequestID $RequestId
$today =Get-Date -Format yyyyMMdd
if($Cert -ne $null)
{
#$CertName = Get-IssuedRequest -CertificationAuthority $CAServer -RequestID $RequestId | Select -ExpandProperty CommonName
certreq -retrieve -config $CAConfig "$RequestId" "$destination_path$cert_Name.crt"
}



