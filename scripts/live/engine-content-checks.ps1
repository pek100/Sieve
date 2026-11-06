# The part of engine-content.ps1 a law can run: it touches no file and no service.

# `powershell -File` binds `-Lists a,b` as the one string "a,b", and -Command binds an
# array, so both are split here. The engine ignores an id it does not know, so a joined
# id would run with no lists at all, and an empty list is refused for the same reason.
function Get-ListIds([string[]]$Lists) {
  $ids = @($Lists -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  if ($ids.Count -eq 0) { throw "-Lists names no list id." }
  return $ids
}

function Set-PolicyLists($policy, [string[]]$Lists) {
  $policy | Add-Member -Force -NotePropertyName lists -NotePropertyValue @(Get-ListIds $Lists)
}
