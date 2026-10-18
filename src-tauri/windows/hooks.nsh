; Sieve's NSIS hooks (tauri.conf.json bundle > windows > nsis > installerHooks).
; The bundle is per machine, so the installer runs elevated and every
; command below runs as the admin who approved the UAC prompt. Plan:
; docs/plans/2026-10-17-https-filtering.md, 1.5.
;
; The engine binary is not a Tauri resource: `pnpm engine:build` (part of
; beforeBuildCommand) builds it, and `File` embeds it when makensis compiles
; the installer. A missing binary fails the build, never the install.
; __FILEDIR__ is read here, outside any macro, so it names this folder.
!define SIEVE_ENGINE_EXE "sieve-engine.exe"
!define SIEVE_ENGINE_SRC "${__FILEDIR__}\..\..\engine\target\release\${SIEVE_ENGINE_EXE}"

; An update replaces a running engine: stop it first (`restore` removes
; Sieve's routes and stops the service; certificates and data stay).
!macro NSIS_HOOK_PREINSTALL
  ${If} ${FileExists} "$INSTDIR\${SIEVE_ENGINE_EXE}"
    DetailPrint "Stopping Sieve's engine"
    nsExec::ExecToLog '"$INSTDIR\${SIEVE_ENGINE_EXE}" restore'
    Pop $0
  ${EndIf}
!macroend

; Copy the engine beside the app (Program Files: only admins can write it,
; plan 1.5) and register its service. Installing changes no network state:
; the engine runs and filters nothing until a later slice turns it on.
!macro NSIS_HOOK_POSTINSTALL
  SetOutPath "$INSTDIR"
  File "/oname=${SIEVE_ENGINE_EXE}" "${SIEVE_ENGINE_SRC}"
  DetailPrint "Installing Sieve's engine service"
  nsExec::ExecToLog '"$INSTDIR\${SIEVE_ENGINE_EXE}" install'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "Sieve's filtering engine could not be set up (exit code $0). Sieve still runs; the installer's details list the step that failed." /SD IDOK
  ${EndIf}
!macroend

; Uninstall removes the service and ProgramData\Sieve (the verb is safe to
; rerun). An uninstall that is part of an update only stops the engine.
!macro NSIS_HOOK_PREUNINSTALL
  ${If} ${FileExists} "$INSTDIR\${SIEVE_ENGINE_EXE}"
    ${If} $UpdateMode = 1
      DetailPrint "Stopping Sieve's engine for the update"
      nsExec::ExecToLog '"$INSTDIR\${SIEVE_ENGINE_EXE}" restore'
    ${Else}
      DetailPrint "Removing Sieve's engine"
      nsExec::ExecToLog '"$INSTDIR\${SIEVE_ENGINE_EXE}" uninstall'
    ${EndIf}
    Pop $0
  ${EndIf}
!macroend

; Tauri's uninstaller deletes only the files it laid down; the engine is ours.
!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
    Delete "$INSTDIR\${SIEVE_ENGINE_EXE}"
    RMDir "$INSTDIR"
  ${EndIf}
!macroend
