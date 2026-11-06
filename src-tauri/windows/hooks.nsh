; Sieve's NSIS hooks (tauri.conf.json bundle > windows > nsis > installerHooks).
; The bundle is per machine, so the installer runs elevated and every
; command below runs as the admin who approved the UAC prompt. Plan:
; docs/plans/2026-10-17-https-filtering.md, 1.5 and 7.
;
; The engine binary is not a Tauri resource: `pnpm engine:build` (part of
; beforeBuildCommand) builds it, and `File` embeds it when makensis compiles
; the installer. A missing binary fails the build, never the install.
; __FILEDIR__ is read here, outside any macro, so it names this folder.
!define SIEVE_ENGINE_EXE "sieve-engine.exe"
!define SIEVE_ENGINE_SRC "${__FILEDIR__}\..\..\engine\target\release\${SIEVE_ENGINE_EXE}"
; Left in a folder this installer created empty and locked (the engine's
; service::image::MARKER_FILE; law 10 keeps the two equal).
!define SIEVE_MARKER "sieve-install.marker"
!define SIEVE_SERVICE_KEY "SYSTEM\CurrentControlSet\Services\sieve-engine"
; The engine's install verb refused a folder users can change
; (service::EXIT_UNSAFE_FOLDER; law 10).
!define SIEVE_EXIT_UNSAFE_FOLDER 3
; Wintun 0.14.1 and its licence, put beside the release engine by
; `pnpm engine:build` (scripts/wintun.mjs checks the DLL's SHA-256 against the
; engine's pin; the engine checks it again before loading it, tun::WINTUN_SHA256).
!define SIEVE_WINTUN_DLL "wintun.dll"
!define SIEVE_WINTUN_LICENSE "wintun-LICENSE.txt"
!define SIEVE_WINTUN_SRC "${__FILEDIR__}\..\..\engine\target\release\${SIEVE_WINTUN_DLL}"
!define SIEVE_WINTUN_LICENSE_SRC "${__FILEDIR__}\..\..\engine\target\release\${SIEVE_WINTUN_LICENSE}"
; The emergency off (plan 1.5): runs `sieve-engine.exe restore` at an admin
; prompt that stays open. Windows file names cannot hold ":", so the plan's
; "Sieve: restore network" is spelled with a hyphen.
!define SIEVE_RESTORE_LINK "$SMPROGRAMS\Sieve - restore network.lnk"

; The install folder (2026-10-18). The engine runs as SYSTEM from it, so
; whoever can write there owns SYSTEM: E:\Sieve inherited "Authenticated
; Users: Modify" from E:\ in the live check. The user keeps choosing the
; folder (Tauri's directory page stays); whatever it is, the hook locks it
; to administrators before any file is copied in:
; - a folder this installer prepared before (it holds SIEVE_MARKER) is
;   locked again;
; - a new or empty folder is locked, checked empty again (nothing slipped in
;   while it was still open) and gets the marker;
; - anything else is refused: locking someone else's files could break them.
; The lock is acl::INSTALL_DIR_SDDL: owner Administrators, inheritance off,
; SYSTEM and Administrators full control, Users read and execute, inherited
; by everything inside (the engine test `the_hooks_icacls_lines_give_the_install_lock`
; runs these exact lines). The engine's install verb then proves it held
; (service::image) before it registers anything, and the service proves it
; again at every start.

Var SieveEngine
Var SieveEngineKept
Var SieveForeign

; $SieveForeign: the first entry of $INSTDIR when the folder holds files and
; no marker (a folder this installer did not prepare), else "".
Function SieveForeignEntry
  Push $R8
  Push $R9
  StrCpy $SieveForeign ""
  ${IfNot} ${FileExists} "$INSTDIR\${SIEVE_MARKER}"
    FindFirst $R8 $R9 "$INSTDIR\*"
    ${DoWhile} $R9 != ""
      ${If} $R9 != "."
      ${AndIf} $R9 != ".."
        StrCpy $SieveForeign $R9
        ${ExitDo}
      ${EndIf}
      FindNext $R8 $R9
    ${Loop}
    FindClose $R8
  ${EndIf}
  Pop $R9
  Pop $R8
FunctionEnd

!macro SIEVE_REFUSE_FOREIGN
  MessageBox MB_ICONSTOP|MB_OK "$INSTDIR already holds files Sieve's installer did not put there ($SieveForeign).$\r$\n$\r$\nSieve's engine runs as SYSTEM, so Sieve locks its folder so that only administrators can change it. Doing that here could break those files. Choose an empty or new folder." /SD IDOK
!macroend

; Tauri's directory page (template: MUI_PAGE_DIRECTORY, no config switch for
; it) checks the choice when the user clicks Next, so a foreign folder is
; refused there, before anything is uninstalled or copied.
!define MUI_DIRECTORYPAGE_VERIFYONLEAVE
Function .onVerifyInstDir
  Call SieveForeignEntry
  ${If} $SieveForeign != ""
    !insertmacro SIEVE_REFUSE_FOREIGN
    Abort
  ${EndIf}
FunctionEnd

; One icacls call on $INSTDIR; a failure stops the install.
!macro SIEVE_ICACLS ARGS
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR" ${ARGS}'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "Sieve could not lock $INSTDIR so that only administrators can change it (icacls ${ARGS}: exit code $0). Nothing of Sieve was installed there." /SD IDOK
    Abort
  ${EndIf}
!macroend

; Runs in the install section after Tauri's SetOutPath created $INSTDIR and
; before the first File. The order leaves no moment with a user-writable
; file in the folder: owner first (a user who made the folder can no longer
; rewrite its ACL), then the inherited ACEs go, then the known broad grants,
; then ours.
Function SieveLockInstallDir
  Call SieveForeignEntry
  ${If} $SieveForeign != ""
    !insertmacro SIEVE_REFUSE_FOREIGN
    Abort
  ${EndIf}
  DetailPrint "Locking $INSTDIR so that only administrators can change it"
  !insertmacro SIEVE_ICACLS '/setowner *S-1-5-32-544'
  !insertmacro SIEVE_ICACLS '/inheritance:r'
  !insertmacro SIEVE_ICACLS '/remove:g *S-1-1-0 *S-1-5-11 *S-1-5-32-545 *S-1-5-4 *S-1-3-0'
  !insertmacro SIEVE_ICACLS '/grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX'
  ${IfNot} ${FileExists} "$INSTDIR\${SIEVE_MARKER}"
    ; Still empty now that it is locked: nothing slipped in before.
    Call SieveForeignEntry
    ${If} $SieveForeign != ""
      !insertmacro SIEVE_REFUSE_FOREIGN
      Abort
    ${EndIf}
    FileOpen $0 "$INSTDIR\${SIEVE_MARKER}" w
    FileWrite $0 "Sieve's installer created this folder and locked it so that only administrators can change it. Sieve's engine checks that lock at every start.$\r$\n"
    FileClose $0
  ${EndIf}
FunctionEnd

; $SieveEngine: the exe the sieve-engine service is registered with (its
; ImagePath, quotes stripped as service::image_exe does), so an older build
; in another folder is still stopped and removed; else $INSTDIR's.
!macro SIEVE_REGISTERED_ENGINE
  Push $R8
  Push $R9
  ReadRegStr $SieveEngine HKLM "${SIEVE_SERVICE_KEY}" "ImagePath"
  ExpandEnvStrings $SieveEngine $SieveEngine
  StrCpy $R9 $SieveEngine 1
  ${If} $R9 == '"'
    StrCpy $SieveEngine $SieveEngine "" 1
    StrCpy $R8 0
    ${Do}
      StrCpy $R9 $SieveEngine 1 $R8
      ${IfThen} $R9 == "" ${|} ${ExitDo} ${|}
      ${IfThen} $R9 == '"' ${|} ${ExitDo} ${|}
      IntOp $R8 $R8 + 1
    ${Loop}
    StrCpy $SieveEngine $SieveEngine $R8
  ${EndIf}
  ${If} $SieveEngine == ""
    StrCpy $SieveEngine "$INSTDIR\${SIEVE_ENGINE_EXE}"
  ${EndIf}
  Pop $R9
  Pop $R8
!macroend

; An update replaces a running engine: stop it first (`restore` removes
; Sieve's routes and stops the service; certificates and data stay). Then
; lock the folder, before Tauri copies the first file.
!macro NSIS_HOOK_PREINSTALL
  !insertmacro SIEVE_REGISTERED_ENGINE
  ${If} ${FileExists} "$SieveEngine"
    DetailPrint "Stopping Sieve's engine ($SieveEngine)"
    nsExec::ExecToLog '"$SieveEngine" restore'
    Pop $0
  ${EndIf}
  Call SieveLockInstallDir
!macroend

; Copy the engine, Wintun and its licence beside the app (the folder is
; locked, so they inherit the lock; the install verb then checks every file
; beside the exe), add the restore shortcut, and register the service.
; Installing changes no network state: the engine routes nothing until the
; user turns "Route traffic through the engine" on.
!macro NSIS_HOOK_POSTINSTALL
  SetOutPath "$INSTDIR"
  File "/oname=${SIEVE_ENGINE_EXE}" "${SIEVE_ENGINE_SRC}"
  File "/oname=${SIEVE_WINTUN_DLL}" "${SIEVE_WINTUN_SRC}"
  File "/oname=${SIEVE_WINTUN_LICENSE}" "${SIEVE_WINTUN_LICENSE_SRC}"
  StrCpy $SieveEngine "$INSTDIR\${SIEVE_ENGINE_EXE}"
  CreateShortCut "${SIEVE_RESTORE_LINK}" "$SYSDIR\cmd.exe" '/k ""$SieveEngine" restore"' "$SieveEngine" 0
  ; Run as administrator: the link's SLDF_RUNAS_USER flag (byte 0x15, bit 0x20).
  FileOpen $1 "${SIEVE_RESTORE_LINK}" a
  FileSeek $1 0x15 SET
  FileReadByte $1 $2
  IntOp $2 $2 | 0x20
  FileSeek $1 0x15 SET
  FileWriteByte $1 $2
  FileClose $1
  DetailPrint "Installing Sieve's engine service"
  nsExec::ExecToLog '"$SieveEngine" install'
  Pop $0
  ${If} $0 = ${SIEVE_EXIT_UNSAFE_FOLDER}
    MessageBox MB_ICONSTOP|MB_OK "Sieve's filtering engine was not set up: users who are not administrators can change files in $INSTDIR or a folder above it, and the engine runs as SYSTEM. Sieve still runs; the installer's details list what was found. Reinstall Sieve into an empty or new folder." /SD IDOK
  ${ElseIf} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "Sieve's filtering engine could not be set up (exit code $0). Sieve still runs; the installer's details list the step that failed." /SD IDOK
  ${EndIf}
!macroend

; Uninstall removes the service and ProgramData\Sieve, using the engine the
; service is registered with. When the verb fails, its exe, the folder's other
; files and the shortcut stay, because the verb's rerun needs them. An uninstall
; that is part of an update only stops the engine.
!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro SIEVE_REGISTERED_ENGINE
  ${If} ${FileExists} "$SieveEngine"
    ${If} $UpdateMode = 1
      DetailPrint "Stopping Sieve's engine for the update"
      nsExec::ExecToLog '"$SieveEngine" restore'
      Pop $0
    ${Else}
      DetailPrint "Removing Sieve's engine"
      nsExec::ExecToLog '"$SieveEngine" uninstall'
      Pop $0
      ${If} $0 != 0
        StrCpy $SieveEngineKept 1
        MessageBox MB_ICONEXCLAMATION|MB_OK "Sieve's engine could not be removed completely (exit code $0), so $SieveEngine was left in place. It does not start by itself. To finish, install Sieve and uninstall it again, or run this at an administrator prompt:$\r$\n$\r$\n$\"$SieveEngine$\" uninstall" /SD IDOK
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend

; Tauri's uninstaller deletes only the files it laid down; the engine and
; the marker are ours. $SieveEngine is the registered engine, which an older
; build may have left in another folder.
!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
  ${AndIf} $SieveEngineKept != 1
    Delete "$SieveEngine"
    Delete "$INSTDIR\${SIEVE_ENGINE_EXE}"
    Delete "$INSTDIR\${SIEVE_WINTUN_DLL}"
    Delete "$INSTDIR\${SIEVE_WINTUN_LICENSE}"
    Delete "${SIEVE_RESTORE_LINK}"
    Delete "$INSTDIR\${SIEVE_MARKER}"
    RMDir "$INSTDIR"
  ${EndIf}
!macroend
