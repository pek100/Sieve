# A disposable Windows VM on Google Cloud for Sieve's live checks, so routes, DNS and
# certificates change there and not on this PC. Every resource it makes is named
# sieve-test*, and -Action delete removes the VM and its network.
#
#   powershell -NoProfile -File scripts\live\gcp-test-vm.ps1 -Project <id> -Action create
#   ... -Action status | start | stop | delete
#   ... -Action guard -BillingAccount <id>   the budget, the kill switch and the CPU quota
#
# create STARTS BILLING, about $0.38 an hour while running plus the disk until deleted.
# stop ends the hourly charge only; the disk bills until delete. A shutdown from inside
# Windows does not count as stop unless the status below says TERMINATED.
# Each run stops by itself after 12 hours (max-run-duration), so a forgotten VM costs
# about $5 at most before the disk-only rate applies.
#
# Google has no hard spending cap. guard makes passing the limit unlikely, not impossible:
# budget reports lag, so the kill switch fires below the owner's limit. Amounts are in the
# billing account's currency. The owner's limit was $60; on the ILS account these assume
# 3 ILS to the dollar, lower than the real rate, so they err towards stopping early.
param(
  [Parameter(Mandatory = $true)][string]$Project,
  [Parameter(Mandatory = $true)][ValidateSet("create", "status", "start", "stop", "delete", "guard")][string]$Action,
  [string]$Zone = "us-central1-a",
  [string]$Region = "us-central1",
  [string]$BillingAccount = "",
  [int]$BudgetAmount = 180,
  [int]$KillAt = 135,
  [string]$KeyFile = "$HOME\.ssh\sieve_gcp_ed25519.pub",
  [string]$SshUser = "sieve"
)
$ErrorActionPreference = "Stop"
# A prompt would hang an unattended run.
$env:CLOUDSDK_CORE_DISABLE_PROMPTS = "1"

$Vm = "sieve-test-vm"
$Network = "sieve-test"
$Firewall = "sieve-test-admin"
$Topic = "sieve-test-budget"
$Kill = "sieve-test-kill"
$KillAccount = "$Kill@$Project.iam.gserviceaccount.com"
$Common = @("--project", $Project)

function Invoke-Gcloud {
  & gcloud @args
  if ($LASTEXITCODE -ne 0) { throw "gcloud $($args -join ' ') failed with exit code $LASTEXITCODE" }
}

# Whether a read succeeds. Under Stop, Windows PowerShell turns redirected stderr into a throw.
function Test-Gcloud {
  $ErrorActionPreference = "Continue"
  & gcloud @args *> $null
  $LASTEXITCODE -eq 0
}

switch ($Action) {
  "create" {
    if (-not (Test-Path -LiteralPath $KeyFile)) { throw "No SSH public key at $KeyFile" }
    $key = (Get-Content -Raw -Encoding UTF8 -LiteralPath $KeyFile).Trim()
    # Only this PC's current address may reach SSH and RDP. If it changes, rerun create.
    $ip = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 20).ToString().Trim()
    if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw "Could not read this PC's public IPv4 address: '$ip'" }

    if (-not (Test-Gcloud compute networks describe $Network @Common)) { Invoke-Gcloud compute networks create $Network --subnet-mode=auto @Common }

    if (-not (Test-Gcloud compute firewall-rules describe $Firewall @Common)) {
      Invoke-Gcloud compute firewall-rules create $Firewall --network=$Network --allow="tcp:22,tcp:3389" --source-ranges="$ip/32" @Common
    } else {
      Invoke-Gcloud compute firewall-rules update $Firewall --source-ranges="$ip/32" @Common
    }

    $metadata = New-TemporaryFile
    try {
      Set-Content -LiteralPath $metadata.FullName -Value "${SshUser}:$key" -Encoding Ascii
      Invoke-Gcloud compute instances create $Vm --zone=$Zone --machine-type=n2-standard-4 `
        --image-family=windows-2025 --image-project=windows-cloud `
        --boot-disk-size=128GB --boot-disk-type=pd-balanced --network=$Network `
        --max-run-duration=12h --instance-termination-action=STOP `
        --metadata="enable-windows-ssh=TRUE,serial-port-enable=TRUE,sysprep-specialize-script-cmd=googet -noconfirm=true install google-compute-engine-ssh" `
        --metadata-from-file="ssh-keys=$($metadata.FullName)" @Common
    } finally {
      Remove-Item -LiteralPath $metadata.FullName -ErrorAction SilentlyContinue
    }
    Invoke-Gcloud compute instances describe $Vm --zone=$Zone --format="value(status,networkInterfaces[0].accessConfigs[0].natIP)" @Common
  }
  "status" { Invoke-Gcloud compute instances describe $Vm --zone=$Zone --format="value(status,networkInterfaces[0].accessConfigs[0].natIP)" @Common }
  "start" { Invoke-Gcloud compute instances start $Vm --zone=$Zone @Common }
  "stop" { Invoke-Gcloud compute instances stop $Vm --zone=$Zone @Common }
  "guard" {
    if (-not $BillingAccount) { throw "guard needs -BillingAccount" }
    if (-not (Test-Gcloud pubsub topics describe $Topic @Common)) { Invoke-Gcloud pubsub topics create $Topic @Common }
    # Budgets publish as this Google-owned account.
    Invoke-Gcloud pubsub topics add-iam-policy-binding $Topic --member="serviceAccount:billing-budget-alert@system.gserviceaccount.com" --role="roles/pubsub.publisher" --format=none @Common

    if (-not (Test-Gcloud iam service-accounts describe $KillAccount @Common)) { Invoke-Gcloud iam service-accounts create $Kill --display-name="Sieve test kill switch" @Common }
    Invoke-Gcloud projects add-iam-policy-binding $Project --member="serviceAccount:$KillAccount" --role="roles/billing.projectManager" --condition=None --format=none

    $source = Join-Path $PSScriptRoot "gcp-killswitch"
    if (-not (Test-Gcloud functions describe $Kill --gen2 --region=$Region @Common)) {
      Invoke-Gcloud functions deploy $Kill --gen2 --runtime=python312 --region=$Region --source=$source --entry-point=on_budget `
        --trigger-topic=$Topic --run-service-account=$KillAccount --trigger-service-account=$KillAccount --max-instances=1 --memory=256MB `
        --no-allow-unauthenticated --set-env-vars="KILL_AT=$KillAt,PROJECT_ID=$Project" --format=none @Common
    }
    Invoke-Gcloud projects add-iam-policy-binding $Project --member="serviceAccount:$KillAccount" --role="roles/run.invoker" --condition=None --format=none

    # This project only: the billing account also pays for other projects.
    $existing = & gcloud billing budgets list --billing-account=$BillingAccount --filter="displayName=sieve-test" --format="value(name)"
    if ($existing) { "Budget already exists: $existing" } else {
      $currency = & gcloud billing accounts describe $BillingAccount --format="value(currencyCode)"
      # A budget with no currency would read the amount in whatever the account bills in.
      if (-not $currency) { throw "Could not read the billing account's currency; nothing was created. Run guard again." }
      Invoke-Gcloud billing budgets create --billing-account=$BillingAccount --display-name="sieve-test" `
        --filter-projects="projects/$Project" --budget-amount="$BudgetAmount$currency" `
        --threshold-rule=percent=0.5 --threshold-rule=percent=0.75 --threshold-rule=percent=1.0 `
        --notifications-rule-pubsub-topic="projects/$Project/topics/$Topic" --format=none
    }
  }
  "delete" {
    # Disk goes with the VM (auto-delete is the default for a boot disk). The project, its
    # kill switch and budget stay until the project is deleted.
    Invoke-Gcloud compute instances delete $Vm --zone=$Zone @Common
    Invoke-Gcloud compute firewall-rules delete $Firewall @Common
    Invoke-Gcloud compute networks delete $Network @Common
    "Deleted the VM and its network. To remove the rest: gcloud projects delete $Project"
  }
}
