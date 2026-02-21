import os, sys, shutil, subprocess, ctypes, time, tempfile, platform
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

BANNER = [
    r"  _   _           __        ___       ",
    r" | | | | _____  __\ \      / (_)_ __  ",
    r" | |_| |/ _ \ \/ / \ \ /\ / /| | '_ \ ",
    r" |  _  |  __/>  <   \ V  V / | | | | |",
    r" |_| |_|\___/_/\_\   \_/\_/  |_|_| |_|",
    r"",
    r"         Hex-win10 Tweaker v1.0",
    r"     made with <3 by @hex1 on TikTok",
]



def banner():
    os.system("cls" if os.name == "nt" else "clear")
    for line in BANNER:
        for ch in line:
            sys.stdout.write(ch)
            sys.stdout.flush()
            time.sleep(0.011)
        sys.stdout.write("\n")
        sys.stdout.flush()
    print()

def admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run(cmd, timeout=12):
    try:
        subprocess.run(cmd, shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout)
    except:
        pass

def rout(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=timeout)
        return r.returncode == 0, r.stdout.strip()
    except:
        return False, ""

def ps(script, timeout=15):
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-WindowStyle", "Hidden", "-Command", script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout)
    except:
        pass

def reg(content):
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".reg")
        with os.fdopen(fd, "wb") as f:
            f.write(b"\xff\xfe")
            f.write(content.encode("utf-16-le"))
        subprocess.run(f'regedit /s "{tmp}"', shell=True, timeout=10,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass
    finally:
        if tmp:
            try: os.unlink(tmp)
            except: pass

def wipe(path):
    try:
        for item in Path(path).iterdir():
            try:
                if item.is_file() or item.is_symlink():
                    item.unlink(missing_ok=True)
                elif item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
            except:
                pass
    except:
        pass

def gb(b):
    return round(b / 1024 ** 3, 1)

def say(msg):
    print(f"  {msg}...", end=" ", flush=True)

def ok():
    print("done!")

def header(title):
    print()
    print("  " + "─" * 50)
    print(f"  {title}")
    print("  " + "─" * 50)
    print()

def specs():
    print("  System info:")
    print(f"    CPU : {platform.processor() or platform.machine() or 'Unknown'}")
    if HAS_PSUTIL:
        vm = psutil.virtual_memory()
        print(f"    RAM : {gb(vm.total)} GB total  |  {gb(vm.available)} GB free  ({round(vm.percent)}% used)")
        try:
            d = psutil.disk_usage("C:\\")
            print(f"    C:\\ : {gb(d.total)} GB total  |  {gb(d.free)} GB free")
        except:
            pass
    r, out = rout("nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits", 5)
    if r and out:
        p = [x.strip() for x in out.split(",")]
        if len(p) >= 3:
            print(f"    GPU : {p[0]}  |  VRAM {p[1]}/{p[2]} MB")
    print()


def clean():
    header("1. Cache & Temp Cleaner")

    lad = os.environ.get("LOCALAPPDATA", "")
    win = os.environ.get("SystemRoot", r"C:\Windows")
    apd = os.environ.get("APPDATA", "")

    say("Windows temp & junk folders")
    for d in [
        os.environ.get("TEMP", ""),
        os.environ.get("TMP", ""),
        os.path.join(win, "Temp"),
        os.path.join(win, "Prefetch"),
        os.path.join(win, "SoftwareDistribution", "Download"),
        os.path.join(lad, "Temp"),
        os.path.join(lad, "Microsoft", "Windows", "INetCache"),
        os.path.join(lad, "Microsoft", "Windows", "WER"),
        os.path.join(lad, "CrashDumps"),
        os.path.join(apd, "Microsoft", "Windows", "Recent"),
        os.path.join(win, "Logs"),
    ]:
        if d and os.path.isdir(d):
            wipe(d)
    run("rd /s /q %SystemDrive%\\$Recycle.Bin", 8)
    ok()

    say("Browser caches (Chrome, Edge, Brave, Firefox, Opera)")
    for p in [
        os.path.join(lad, "Google", "Chrome", "User Data", "Default", "Cache"),
        os.path.join(lad, "Google", "Chrome", "User Data", "Default", "Code Cache"),
        os.path.join(lad, "Google", "Chrome", "User Data", "Default", "GPUCache"),
        os.path.join(lad, "Microsoft", "Edge", "User Data", "Default", "Cache"),
        os.path.join(lad, "Microsoft", "Edge", "User Data", "Default", "Code Cache"),
        os.path.join(lad, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cache"),
        os.path.join(lad, "Opera Software", "Opera Stable", "Cache"),
        os.path.join(lad, "Vivaldi", "User Data", "Default", "Cache"),
    ]:
        if os.path.isdir(p):
            wipe(p)
    ff = os.path.join(lad, "Mozilla", "Firefox", "Profiles")
    if os.path.isdir(ff):
        try:
            for profile in Path(ff).iterdir():
                for sub in ["cache2", "startupCache", "thumbnails"]:
                    c = profile / sub
                    if c.is_dir():
                        wipe(str(c))
        except:
            pass
    ok()

    say("GPU shader caches (NVIDIA, AMD, Intel)")
    for d in [
        os.path.join(lad, "NVIDIA", "DXCache"),
        os.path.join(lad, "NVIDIA", "GLCache"),
        os.path.join(lad, "NVIDIA", "OptixCache"),
        os.path.join(lad, "D3DSCache"),
        os.path.join(lad, "AMD", "DxCache"),
        os.path.join(lad, "AMD", "DxcCache"),
        os.path.join(lad, "Intel", "ShaderCache"),
    ]:
        if os.path.isdir(d):
            wipe(d)
    ok()

    say("Icon & thumbnail cache")
    wipe(os.path.join(lad, "Microsoft", "Windows", "Explorer"))
    ic = os.path.join(lad, "IconCache.db")
    if os.path.isfile(ic):
        try: os.remove(ic)
        except: pass
    ok()

    say("Windows event logs")
    for log in ["Application", "System", "Setup"]:
        run(f"wevtutil cl {log}", 6)
    ok()

    print()
    print("  Cache & temp clean complete.")


def ram_optimize():
    header("2. RAM Optimizer")

    if HAS_PSUTIL:
        bef = psutil.virtual_memory()
        print(f"  Before: {gb(bef.available)} GB free  ({round(bef.percent)}% used)")
        print()

    say("Trimming all process working sets")
    if HAS_PSUTIL:
        SKIP = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
                "services.exe", "lsass.exe"}
        k32 = ctypes.windll.kernel32
        snap = [(p.info["pid"], p.info["name"])
                for p in psutil.process_iter(["pid", "name"])]
        for pid, name in snap:
            try:
                if (name or "").lower() in SKIP:
                    continue
                h = k32.OpenProcess(0x0100, False, pid)
                if h:
                    k32.SetProcessWorkingSetSize(
                        h, ctypes.c_size_t(-1), ctypes.c_size_t(-1))
                    k32.CloseHandle(h)
            except:
                pass
    ok()

    say("Forcing .NET garbage collection")
    ps("[GC]::Collect(2,[System.GCCollectionMode]::Forced,$true,$true);"
       "[GC]::WaitForPendingFinalizers()", 10)
    ok()

    say("Correct memory management registry values")
    mm = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    pf = mm + r"\PrefetchParameters"
    for key, name, val in [
        (mm, "DisablePagingExecutive", 0),   # never lock kernel in RAM
        (mm, "LargeSystemCache",       0),
        (mm, "PoolUsageMaximum",       80),  # safe kernel pool limit
        (mm, "PagedPoolSize",          0),   # auto
        (mm, "IoPageLockLimit",        0),   # auto — no arbitrary lock
        (pf, "EnablePrefetcher",       3),
        (pf, "EnableSuperfetch",       3),
    ]:
        run(f'reg add "{key}" /v "{name}" /t REG_DWORD /d {val} /f', 5)
    ok()

    say("Right-sizing pagefile for your RAM")
    if HAS_PSUTIL:
        tgb = gb(psutil.virtual_memory().total)
        if tgb <= 8:    pi, pm = 8192,  16384
        elif tgb <= 16: pi, pm = 4096,  8192
        elif tgb <= 32: pi, pm = 2048,  4096
        else:           pi, pm = 1024,  2048
        ps(
            "$cs=Get-WmiObject Win32_ComputerSystem;"
            "$cs.AutomaticManagedPagefile=$false;$cs.Put()|Out-Null;"
            "$p=Get-WmiObject -Class Win32_PageFileSetting -EA SilentlyContinue;"
            f"if($p){{$p.InitialSize={pi};$p.MaximumSize={pm};$p.Put()|Out-Null}}",
            12)
    ok()

    say("Disabling background app memory drain")
    run('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion'
        '\\BackgroundAccessApplications" '
        '/v GlobalUserDisabled /t REG_DWORD /d 1 /f', 5)
    ok()

    print()
    if HAS_PSUTIL:
        aft = psutil.virtual_memory()
        freed = round(gb(aft.available) - gb(bef.available), 1)
        print(f"  After:  {gb(aft.available)} GB free  ({round(aft.percent)}% used)")
        if freed > 0:
            print(f"  Freed:  +{freed} GB")
    print()
    print("  RAM optimizer complete.")


def fps_boost():
    header("3. FPS Booster")

    say("Activating high performance power plan")
    run("powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", 8)
    # PROCTHROTTLEMIN=0 so plan allows full idle too — only BOOST is forced
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 0",   6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100", 6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 2",     6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTPOL 100",    6)
    run("powercfg -h off", 6)
    ok()

    say("0.5ms timer resolution")
    try:
        ctypes.windll.ntdll.NtSetTimerResolution(
            5000, True, ctypes.byref(ctypes.c_ulong()))
    except:
        pass
    ok()

    say("Disabling CPU core parking")
    run(
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\'
        '54533251-82be-4824-96c1-47b60b740d00\\'
        '0cc5b647-c1df-4637-891a-dec35c318583" '
        '/v ValueMax /t REG_DWORD /d 0 /f', 5)
    run(
        'powercfg /SETACVALUEINDEX SCHEME_CURRENT '
        '54533251-82be-4824-96c1-47b60b740d00 '
        '0cc5b647-c1df-4637-891a-dec35c318583 0', 6)
    ok()

    say("Game scheduler & GPU priority")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT"
        "\\CurrentVersion\\Multimedia\\SystemProfile]\r\n"
        '"NetworkThrottlingIndex"=dword:ffffffff\r\n'
        '"SystemResponsiveness"=dword:00000014\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT"
        "\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games]\r\n"
        '"GPU Priority"=dword:00000008\r\n'
        '"Priority"=dword:00000006\r\n'
        '"Scheduling Category"="High"\r\n'
        '"SFIO Priority"="High"\r\n'
        '"Background Only"="False"\r\n'
        '"Clock Rate"=dword:00002710\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl]\r\n"
        '"Win32PrioritySeparation"=dword:00000028\r\n'
        "\r\n"
    )
    ok()

    say("Hardware-accelerated GPU scheduling (HAGS)")
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers" '
        '/v HwSchMode /t REG_DWORD /d 2 /f', 5)
    ok()

    say("Disabling GameDVR / GameBar overlay")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR]\r\n"
        '"AppCaptureEnabled"=dword:00000000\r\n'
        '"HistoricalCaptureEnabled"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR]\r\n"
        '"AllowGameDVR"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\System\\GameConfigStore]\r\n"
        '"GameDVR_Enabled"=dword:00000000\r\n'
        '"GameDVR_FSEBehaviorMode"=dword:00000002\r\n'
        '"GameDVR_DXGIHonorFSEWindowsCompatible"=dword:00000001\r\n'
        '"GameDVR_HonorUserFSEBehaviorMode"=dword:00000001\r\n'
        '"GameDVR_EFSEFeatureFlags"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\GameBar]\r\n"
        '"AllowAutoGameMode"=dword:00000001\r\n'
        '"AutoGameModeEnabled"=dword:00000001\r\n'
        '"UseNexusForGameBarEnabled"=dword:00000000\r\n'
        "\r\n"
    )
    ok()

    say("NTFS last-access timestamp off")
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem" '
        '/v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f', 5)
    ok()

    say("Boosting any currently running game processes")
    if HAS_PSUTIL:
        GAMES = {
            "cs2.exe","csgo.exe","valorant.exe","fortnite.exe","r5apex.exe",
            "eldenring.exe","witcher3.exe","cyberpunk2077.exe","rainbowsix.exe",
            "overwatch.exe","gta5.exe","rocketleague.exe","minecraft.exe","javaw.exe",
            "tslgame.exe","bf4.exe","bf2042.exe","destiny2.exe","cod.exe",
            "warzone.exe","escapefromtarkov.exe","halo_infinite.exe",
            "starfield.exe","dota2.exe","leagueclient.exe","league of legends.exe",
        }
        snap = [(p.info["pid"], p.info["name"])
                for p in psutil.process_iter(["pid", "name"])]
        n = 0
        for pid, name in snap:
            try:
                if (name or "").lower() in GAMES:
                    psutil.Process(pid).nice(psutil.HIGH_PRIORITY_CLASS)
                    n += 1
            except:
                pass
        if n:
            print(f"\n    {n} game process(es) prioritized", end="")
    ok()

    print()
    print("  FPS boost complete.")
    print("  Note: timer resolution resets on reboot — that is normal.")



BG_PROCS = {
    "msedge.exe", "microsoftedge.exe", "microsoftedgeupdateml.exe",
    "onedrive.exe", "onedrivesetup.exe",
    "skype.exe", "skypeapp.exe",
    "teams.exe", "ms-teams.exe",
    "yourphone.exe", "phoneexperiencehost.exe",
    "cortana.exe", "lockapp.exe",
    "gamebar.exe", "gamebarftserver.exe", "gamebarpresencewriter.exe",
    "xboxapp.exe", "xboxgameoverlay.exe",
    "widgetservice.exe", "widgets.exe",
    "searchapp.exe", "searchui.exe",
    "tabtip.exe", "tabtip32.exe",
    "winstore.app.exe", "speechruntime.exe",
    "wuauclt.exe", "musnotification.exe", "musnotificationux.exe",
    "usocoreworker.exe", "uhssvc.exe",
    "aitstatic.exe", "compattelrunner.exe",
    "smartscreen.exe", "backgroundtaskhost.exe",
    "microsoftedgeupdate.exe",
    "nvtelemetrycontainer.exe",
    "adobeupdater.exe", "adobearm.exe",
}

BG_SERVICES = [
    "DiagTrack", "dmwappushservice", "WerSvc", "PcaSvc",
    "XblGameSave", "XblAuthManager", "MapsBroker", "PhoneSvc",
    "TabletInputService", "icssvc", "RetailDemo", "DusmSvc",
    "WalletService", "MessagingService", "PimIndexMaintenanceSvc",
    "OneSyncSvc", "UnistoreSvc", "UserDataSvc",
    "wisvc", "diagsvc", "wercplsupport",
    "WbioSrvc", "lfsvc", "Fax", "WMPNetworkSvc",
    "RemoteRegistry", "TrkWks", "lltdsvc",
]

# processes that must never be touched
SAFE_PROCS = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "dwm.exe", "explorer.exe", "conhost.exe", "fontdrvhost.exe",
    "runtimebroker.exe", "sihost.exe", "ctfmon.exe", "taskhostw.exe",
    "audiodg.exe", "dllhost.exe", "taskmgr.exe",
    "python.exe", "pythonw.exe", "cmd.exe",
}

def kill_background():
    header("4. Background Process Killer")

    say("Killing useless background processes")
    killed = 0
    if HAS_PSUTIL:
        snap = [(p.info["pid"], p.info["name"])
                for p in psutil.process_iter(["pid", "name"])]
        for pid, name in snap:
            try:
                n = (name or "").lower()
                if n in SAFE_PROCS:
                    continue
                if n in BG_PROCS:
                    psutil.Process(pid).kill()
                    killed += 1
                    time.sleep(0.04)
            except:
                pass
    ok()
    print(f"    {killed} processes killed")

    say("Stopping background services (serialized)")
    chunks = [BG_SERVICES[i:i+4] for i in range(0, len(BG_SERVICES), 4)]
    for chunk in chunks:
        for svc in chunk:
            run(f"sc stop {svc}", 5)
            time.sleep(0.06)
    ok()

    say("Removing bloat startup entries")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"
        '"OneDrive"=-\r\n'
        '"Skype"=-\r\n'
        '"Teams"=-\r\n'
        '"MicrosoftEdgeUpdate"=-\r\n'
        '"YourPhone"=-\r\n'
        '"PhoneExperienceHost"=-\r\n'
        '"AdobeUpdater"=-\r\n'
        '"Cortana"=-\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"
        '"OneDrive"=-\r\n'
        '"MicrosoftEdgeUpdate"=-\r\n'
        '"Teams"=-\r\n'
        '"Cortana"=-\r\n'
        "\r\n"
    )
    ok()

    say("Disabling telemetry scheduled tasks")
    for task in [
        "Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
        "Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask",
        "Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
        "Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
        "Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
        "Microsoft\\Windows\\AutochkProxy",
        "Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",
    ]:
        run(f'schtasks /Change /TN "{task}" /Disable', 4)
    ok()

    say("Disabling telemetry & advertising registry")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection]\r\n"
        '"AllowTelemetry"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo]\r\n"
        '"Enabled"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization]\r\n"
        '"DODownloadMode"=dword:00000000\r\n'
        "\r\n"
    )
    ok()

    print()
    print("  Background killer complete.")



def sys_optimize():
    header("5. System Optimizer")

    say("Removing all animations & transitions")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows"
        "\\CurrentVersion\\Explorer\\VisualEffects]\r\n"
        '"VisualFXSetting"=dword:00000002\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Control Panel\\Desktop]\r\n"
        '"MenuShowDelay"="0"\r\n'
        '"DragFullWindows"="0"\r\n'
        '"FontSmoothing"="2"\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Control Panel\\Desktop\\WindowMetrics]\r\n"
        '"MinAnimate"="0"\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows"
        "\\CurrentVersion\\Explorer\\Advanced]\r\n"
        '"TaskbarAnimations"=dword:00000000\r\n'
        '"ListviewShadow"=dword:00000000\r\n'
        '"ListviewAlphaSelect"=dword:00000000\r\n'
        '"ExtendedUIHoverTime"=dword:00000001\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\DWM]\r\n"
        '"EnableAeroPeek"=dword:00000000\r\n'
        '"AlwaysHibernateThumbnails"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows"
        "\\CurrentVersion\\Themes\\Personalize]\r\n"
        '"EnableTransparency"=dword:00000000\r\n'
        "\r\n"
    )
    # also apply live via SPI
    try:
        class AI(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("iMinAnimate", ctypes.c_int)]
        ai = AI()
        ai.cbSize = ctypes.sizeof(AI)
        ai.iMinAnimate = 0
        ctypes.windll.user32.SystemParametersInfoW(
            0x0048, ctypes.sizeof(AI), ctypes.byref(ai), 3)
    except:
        pass
    ok()

    say("Disabling transparency")
    run('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion'
        '\\Themes\\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f', 5)
    ok()

    say("Disabling screen saver")
    run('reg add "HKCU\\Control Panel\\Desktop" '
        '/v ScreenSaveActive /t REG_SZ /d 0 /f', 5)
    ok()

    say("Disabling search indexing (WSearch)")
    run("sc stop WSearch", 6)
    run("sc config WSearch start= disabled", 6)
    ok()

    say("Disabling Cortana & start menu web search")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search]\r\n"
        '"AllowCortana"=dword:00000000\r\n'
        '"DisableWebSearch"=dword:00000001\r\n'
        '"ConnectedSearchUseWeb"=dword:00000000\r\n'
        "\r\n"
    )
    ok()

    say("Sane app & service shutdown timeouts")
    run('reg add "HKCU\\Control Panel\\Desktop" /v AutoEndTasks /t REG_SZ /d 0 /f', 5)
    run('reg add "HKCU\\Control Panel\\Desktop" /v HungAppTimeout /t REG_SZ /d 5000 /f', 5)
    run('reg add "HKCU\\Control Panel\\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 5000 /f', 5)
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control" '
        '/v WaitToKillServiceTimeout /t REG_SZ /d 5000 /f', 5)
    ok()

    say("Disabling noisy Explorer notifications")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows"
        "\\CurrentVersion\\Explorer\\Advanced]\r\n"
        '"ShowSyncProviderNotifications"=dword:00000000\r\n'
        '"Start_TrackProgs"=dword:00000000\r\n'
        '"EnableBalloonTips"=dword:00000000\r\n'
        "\r\n"
    )
    ok()

    say("Disabling hibernation (frees hiberfil.sys RAM)")
    run("powercfg -h off", 6)
    ok()

    print()
    print("  System optimizer complete.")
    print("  Log out and back in (or restart) for visual changes.")


def nvidia_optimize():
    header("6. NVIDIA Optimizer")

    r, out = rout(
        "nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits", 5)
    if not (r and out):
        print("  No NVIDIA GPU detected — skipping.")
        return

    parts = [x.strip() for x in out.split(",")]
    print(f"  GPU : {parts[0]}  ({parts[1] if len(parts) > 1 else '?'} MB VRAM)")
    print()

    say("Auto-boost off, persistence mode on")
    run("nvidia-smi --auto-boost-default=0", 6)
    run("nvidia-smi --persistence-mode=1",   6)
    ok()

    say("Disabling NVIDIA telemetry services")
    run('reg add "HKLM\\SOFTWARE\\NVIDIA Corporation\\NvControlPanel2\\Client" '
        '/v OptInOrOutPreference /t REG_DWORD /d 0 /f', 4)
    for key in ["EnableRID44231", "EnableRID64640", "EnableRID66610"]:
        run(f'reg add "HKLM\\SOFTWARE\\NVIDIA Corporation\\Global\\FTS" '
            f'/v {key} /t REG_DWORD /d 0 /f', 4)
    for svc in ["NvTelemetryContainer", "NvSvc"]:
        run(f"sc stop {svc}", 5)
        run(f"sc config {svc} start= disabled", 5)
        time.sleep(0.05)
    ok()

    say("Prefer Maximum Performance (PowerMizer = max)")
    nv = (r"HKLM\SYSTEM\CurrentControlSet\Control\Class"
          r"\{4d36e968-e325-11ce-bfc1-08002be10318}\0000")
    for name, val in [
        ("PowerMizerEnable",  1),   # enable powermizer control
        ("PowerMizerLevel",   1),   # 1 = max performance
        ("PowerMizerLevelAC", 1),   # same on AC power
    ]:
        run(f'reg add "{nv}" /v {name} /t REG_DWORD /d {val} /f', 4)
    ok()

    say("Low latency driver flags")
    for name, val in [
        ("EnableMidBufferPreemption", 0),
        ("EnableCEPreemption",        0),
        ("RMHdcpKeygroupSize",        4),
    ]:
        run(f'reg add "{nv}" /v {name} /t REG_DWORD /d {val} /f', 4)
    ok()

    say("Hardware GPU scheduling + TDR tuning")
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers" '
        '/v HwSchMode /t REG_DWORD /d 2 /f', 5)
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers" '
        '/v TdrDelay /t REG_DWORD /d 10 /f', 5)
    ok()

    say("Games task GPU priority = 8")
    run('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
        '\\Multimedia\\SystemProfile\\Tasks\\Games" '
        '/v "GPU Priority" /t REG_DWORD /d 8 /f', 4)
    ok()

    say("Clearing NVIDIA shader cache")
    lad = os.environ.get("LOCALAPPDATA", "")
    for d in [
        os.path.join(lad, "NVIDIA", "DXCache"),
        os.path.join(lad, "NVIDIA", "GLCache"),
        os.path.join(lad, "NVIDIA", "OptixCache"),
        os.path.join(lad, "D3DSCache"),
    ]:
        if os.path.isdir(d):
            wipe(d)
    ok()

    say("GPU display idle power = 0")
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 0",  6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO DEVICEIDLE 0", 6)
    ok()

    say("Refreshing display driver (brief flicker is normal)")
    try:
        u32  = ctypes.windll.user32
        keys = [0x11, 0x10, 0x5B, 0x42]   # Ctrl+Shift+Win+B
        for k in keys:
            u32.keybd_event(k, 0, 0, 0)
            time.sleep(0.05)
        time.sleep(0.1)
        for k in reversed(keys):
            u32.keybd_event(k, 0, 0x0002, 0)
            time.sleep(0.05)
        time.sleep(2)
    except:
        pass
    ok()

    print()
    print("  NVIDIA optimizer complete.")
    print("  Also apply manually in NVIDIA Control Panel:")
    print("    Manage 3D Settings > Power management > Prefer Maximum Performance")
    print("    Manage 3D Settings > Low Latency Mode > Ultra")


def cpu_reset():
    header("7. CPU Reset")

    say("Switching to Balanced power plan")
    run("powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e", 8)
    ok()

    say("PROCTHROTTLEMIN = 5  (CPU can idle properly)")
    for scheme in [
        "SCHEME_CURRENT",
        "SCHEME_BALANCED",
        "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",   # High Performance GUID
    ]:
        run(f'powercfg /SETACVALUEINDEX "{scheme}" '
            f'SUB_PROCESSOR PROCTHROTTLEMIN 5', 6)
    ok()

    say("PROCTHROTTLEMAX = 100%")
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT  SUB_PROCESSOR PROCTHROTTLEMAX 100", 6)
    run("powercfg /SETACVALUEINDEX SCHEME_BALANCED SUB_PROCESSOR PROCTHROTTLEMAX 100", 6)
    ok()

    say("PERFBOOSTMODE = 1  (normal, not aggressive)")
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT  SUB_PROCESSOR PERFBOOSTMODE 1", 6)
    run("powercfg /SETACVALUEINDEX SCHEME_BALANCED SUB_PROCESSOR PERFBOOSTMODE 1", 6)
    ok()

    say("Re-enabling core parking")
    run(
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\'
        '54533251-82be-4824-96c1-47b60b740d00\\'
        '0cc5b647-c1df-4637-891a-dec35c318583" '
        '/v ValueMax /t REG_DWORD /d 100 /f', 5)
    ok()

    say("Win32PrioritySeparation = 2  (Windows default)")
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" '
        '/v Win32PrioritySeparation /t REG_DWORD /d 2 /f', 5)
    ok()

    say("SystemResponsiveness = 20  (default)")
    run('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
        '\\Multimedia\\SystemProfile" '
        '/v SystemResponsiveness /t REG_DWORD /d 20 /f', 5)
    ok()

    say("DisablePagingExecutive = 0")
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager'
        '\\Memory Management" '
        '/v DisablePagingExecutive /t REG_DWORD /d 0 /f', 5)
    ok()

    say("PoolUsageMaximum = 80")
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager'
        '\\Memory Management" '
        '/v PoolUsageMaximum /t REG_DWORD /d 80 /f', 5)
    ok()

    say("WaitToKillServiceTimeout = 5000 ms")
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control" '
        '/v WaitToKillServiceTimeout /t REG_SZ /d 5000 /f', 5)
    ok()

    say("Re-activating Balanced plan")
    run("powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e", 8)
    ok()

    # verify
    print()
    print("  Verifying:")
    r, out = rout(
        'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" '
        '/v Win32PrioritySeparation', 5)
    val  = out.split()[-1] if (r and out.split()) else "ERR"
    flag = "OK" if val == "0x2" else "!! CHECK"
    print(f"    Win32PrioritySeparation : {val}  {flag}")

    r, out = rout(
        'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager'
        '\\Memory Management" /v DisablePagingExecutive', 5)
    val  = out.split()[-1] if (r and out.split()) else "ERR"
    flag = "OK" if val == "0x0" else "!! CHECK"
    print(f"    DisablePagingExecutive  : {val}  {flag}")

    r, out = rout("powercfg /getactivescheme", 6)
    if r and out:
        label = "Balanced" if "381b4222" in out.lower() else out[:50]
        print(f"    Active power plan       : {label}")

    print()
    print("  CPU reset complete.")
    print("  RESTART YOUR PC for all changes to fully apply.")



def run_all():
    print()
    print("  Running full sequence...")
    clean()
    ram_optimize()
    kill_background()
    sys_optimize()
    fps_boost()
    nvidia_optimize()
    cpu_reset()          # always last
    print()
    print("  " + "═" * 50)
    print("  All done.  RESTART YOUR PC for best results.")
    print("  " + "═" * 50)


def after():
    print()
    ans = input("  Restart PC now? (y/N): ").strip().lower()
    if ans == "y":
        for i in range(5, 0, -1):
            print(f"\r  Restarting in {i}...", end="", flush=True)
            time.sleep(1)
        print()
        run("shutdown /r /t 0")
        return
    print()
    print("  [1] Back to menu")
    print("  [2] Exit")
    print()
    c = input("  Enter: ").strip()
    if c == "1":
        main()
    else:
        sys.exit(0)



def main():
    banner()

    if not admin():
        print("  WARNING: Not running as admin.")
        print("  Right-click the script and choose Run as administrator.\n")

    if not HAS_PSUTIL:
        say("Installing psutil")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "psutil", "--quiet"],
                timeout=60,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            ok()
            print("  Restart the script to enable all features.\n")
        except:
            print("failed  (some RAM features will be skipped)\n")

    specs()

    print("  [1]  Cache & Temp Cleaner")
    print("  [2]  RAM Optimizer")
    print("  [3]  FPS Booster")
    print("  [4]  Background Process Killer")
    print("  [5]  System Optimizer  (no animations / transitions)")
    print("  [6]  NVIDIA Optimizer")
    print("  [7]  CPU Reset")
    print("  [8]  Run All  (1 → 7 in order)")
    print("  [Q]  Quit")
    print()

    c = input("  Enter: ").strip().upper()

    if   c == "1": clean()
    elif c == "2": ram_optimize()
    elif c == "3": fps_boost()
    elif c == "4": kill_background()
    elif c == "5": sys_optimize()
    elif c == "6": nvidia_optimize()
    elif c == "7": cpu_reset()
    elif c == "8": run_all()
    elif c == "Q": sys.exit(0)
    else:
        print("  Invalid — enter 1-8 or Q.")
        return

    print()
    after()


if __name__ == "__main__":
    main()
