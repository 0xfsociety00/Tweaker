import os
import sys
import shutil
import subprocess
import ctypes
import time
import platform
import tempfile
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

BANNER_LINES = [
    r"  _   _           __        ___       ",
    r" | | | | _____  __\ \      / (_)_ __  ",
    r" | |_| |/ _ \ \/ / \ \ /\ / /| | '_ \ ",
    r" |  _  |  __/>  <   \ V  V / | | | | |",
    r" |_| |_|\___/_/\_\   \_/\_/  |_|_| |_|",
    r"",
    r"         Hex-win10 Tweaker v1.7.9",
    r"     made with <3 by @hex1 on TikTok",
]

def banner():
    os.system("cls" if os.name == "nt" else "clear")
    for line in BANNER_LINES:
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

def run(c, timeout=12):
    try:
        subprocess.run(
            c, shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout
        )
    except:
        pass

def rout(c, timeout=10):
    try:
        r = subprocess.run(
            c, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True, timeout=timeout
        )
        return r.returncode == 0, r.stdout.strip()
    except:
        return False, ""

def ps(script, timeout=12):
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout
        )
    except:
        pass

def reg(content):
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".reg")
        with os.fdopen(fd, "wb") as f:
            f.write(b"\xff\xfe")
            f.write(content.encode("utf-16-le"))
        subprocess.run(
            f'regedit /s "{tmp_path}"',
            shell=True, timeout=10,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except:
        pass
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except:
                pass

def svcoff(names):
    for n in names:
        try:
            subprocess.Popen(
                ["sc", "stop", n],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except:
            pass
    time.sleep(2)
    for n in names:
        try:
            subprocess.Popen(
                ["sc", "config", n, "start=", "disabled"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except:
            pass

def gb(b):
    return round(b / 1024 / 1024 / 1024, 1)

def wipe(p):
    try:
        for item in Path(p).iterdir():
            try:
                if item.is_file() or item.is_symlink():
                    item.unlink(missing_ok=True)
                elif item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
            except:
                pass
    except:
        pass

def step(msg):
    print(f"  {msg}...", end=" ", flush=True)

def ok():
    print("done!")

def after():
    print()
    r = input("  Restart your PC now? (y/N): ").strip().lower()
    if r == "y":
        for i in range(5, 0, -1):
            print(f"\r  Restarting in {i}...", end="", flush=True)
            time.sleep(1)
        print()
        run("shutdown /r /t 0")
        return

    print()
    print("  [1] Exit")
    print("  [2] Restart tool")
    print()
    c = input("  Enter: ").strip()
    if c == "2":
        main()
    else:
        sys.exit(0)

def specs():
    print("  System:")
    cpu = platform.processor() or platform.machine() or "Unknown"
    print(f"    CPU     : {cpu}")
    if HAS_PSUTIL:
        ram = psutil.virtual_memory()
        print(f"    RAM     : {gb(ram.total)} GB  |  {gb(ram.available)} GB free  ({round(ram.percent)}% used)")
        try:
            disk = psutil.disk_usage("C:\\")
            print(f"    Drive C : {gb(disk.total)} GB  |  {gb(disk.free)} GB free")
        except:
            pass
    r, out = rout(
        "nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader,nounits",
        timeout=5
    )
    if r and out:
        parts = [x.strip() for x in out.split(",")]
        if len(parts) >= 3:
            print(f"    GPU     : {parts[0]}  |  VRAM {parts[2]}/{parts[1]} MB")
    else:
        ok2, out2 = rout(
            'powershell -NoProfile -NonInteractive -Command "(Get-WmiObject Win32_VideoController | Select-Object -First 1).Name"',
            timeout=8
        )
        if ok2 and out2:
            print(f"    GPU     : {out2.strip()}")
    print()

def pingms(host):
    r, out = rout(f"ping -n 1 -w 500 {host}", timeout=4)
    if r and out:
        for part in out.split():
            p = part.lower()
            if p.startswith("time=") or p.startswith("time<"):
                try:
                    return int(p.replace("time=","").replace("time<","").replace("ms",""))
                except:
                    pass
    return None

def wifiadp():
    r, out = rout("netsh wlan show interfaces", timeout=6)
    adapters = []
    if r and out:
        for line in out.splitlines():
            l = line.strip()
            if l.lower().startswith("name") and ":" in l:
                adapters.append(l.split(":", 1)[1].strip())
    return adapters

def alladp():
    r, out = rout("netsh interface show interface", timeout=6)
    ifaces = []
    if r and out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] in ("Connected", "Enabled"):
                ifaces.append(" ".join(parts[3:]))
    return ifaces

def nvcheck():
    r, out = rout(
        "nvidia-smi --query-gpu=name --format=csv,noheader,nounits",
        timeout=4
    )
    return ok and bool(out)

def amdcheck():
    r, out = rout("wmic path win32_VideoController get name", timeout=6)
    return r and ("AMD" in out.upper() or "RADEON" in out.upper())

def bloat():
    step("Killing bloat processes")
    if not HAS_PSUTIL:
        ok()
        return
    targets = {
        "msedge.exe","microsoftedge.exe","microsoftedgeupdate.exe",
        "searchindexer.exe","searchapp.exe","searchui.exe",
        "onedrive.exe","onedrivesetup.exe",
        "skypeapp.exe","skype.exe",
        "yourphone.exe","phoneexperiencehost.exe",
        "winstore.app.exe",
        "gamebar.exe","gamebarftserver.exe","gamebarpresencewriter.exe",
        "teams.exe","ms-teams.exe",
        "cortana.exe","lockapp.exe",
        "widgetservice.exe","widgets.exe",
        "xboxapp.exe","xboxgameoverlay.exe",
        "speechruntime.exe","tabtip.exe","tabtip32.exe",
    }
    killed = 0
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] and proc.info["name"].lower() in targets:
                proc.kill()
                killed += 1
        except:
            pass
    ok()
    if killed:
        print(f"    {killed} processes killed")

def temp():
    step("Cleaning temp files")
    lad = os.environ.get("LOCALAPPDATA", "")
    win = os.environ.get("SystemRoot", r"C:\Windows")
    apd = os.environ.get("APPDATA", "")
    dirs = {
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
    }
    for d in dirs:
        if d and os.path.isdir(d):
            wipe(d)
    run("rd /s /q %SystemDrive%\\$Recycle.Bin", timeout=8)
    ok()

def browsers():
    step("Cleaning browser caches")
    lad = os.environ.get("LOCALAPPDATA", "")
    paths = [
        os.path.join(lad, "Google",        "Chrome",         "User Data", "Default", "Cache"),
        os.path.join(lad, "Google",        "Chrome",         "User Data", "Default", "Code Cache"),
        os.path.join(lad, "Google",        "Chrome",         "User Data", "Default", "GPUCache"),
        os.path.join(lad, "Microsoft",     "Edge",           "User Data", "Default", "Cache"),
        os.path.join(lad, "Microsoft",     "Edge",           "User Data", "Default", "Code Cache"),
        os.path.join(lad, "Opera Software","Opera Stable",   "Cache"),
        os.path.join(lad, "BraveSoftware", "Brave-Browser",  "User Data", "Default", "Cache"),
        os.path.join(lad, "Vivaldi",       "User Data",      "Default",   "Cache"),
    ]
    for p in paths:
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

def ram():
    step("Optimizing RAM")
    total_gb = gb(psutil.virtual_memory().total) if HAS_PSUTIL else 8
    mm       = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    pf_param = mm + r"\PrefetchParameters"
    sp       = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
    for key, name, val in [
        (mm,       "DisablePagingExecutive", 1),
        (mm,       "LargeSystemCache",       0),
        (mm,       "IoPageLockLimit",        983040),
        (mm,       "SecondLevelDataCache",   512),
        (mm,       "PoolUsageMaximum",       60),
        (mm,       "PagedPoolSize",          0),
        (pf_param, "EnablePrefetcher",       3),
        (pf_param, "EnableSuperfetch",       3),
        (sp,       "SystemResponsiveness",   0),
    ]:
        run(f'reg add "{key}" /v "{name}" /t REG_DWORD /d {val} /f', timeout=5)
    if total_gb <= 8:
        pf_init, pf_max = 8192, 16384
    elif total_gb <= 16:
        pf_init, pf_max = 4096, 8192
    elif total_gb <= 32:
        pf_init, pf_max = 2048, 4096
    else:
        pf_init, pf_max = 1024, 2048
    ps_script = (
        "$cs = Get-WmiObject Win32_ComputerSystem; "
        "$cs.AutomaticManagedPagefile = $false; "
        "$cs.Put() | Out-Null; "
        "$pf = Get-WmiObject -Class Win32_PageFileSetting -ErrorAction SilentlyContinue; "
        "if ($pf) { "
        "  $pf.InitialSize = " + str(pf_init) + "; "
        "  $pf.MaximumSize = " + str(pf_max) + "; "
        "  $pf.Put() | Out-Null "
        "}"
    )
    ps(ps_script, timeout=12)
    if HAS_PSUTIL:
        try:
            k32  = ctypes.windll.kernel32
            SKIP = {
                "system", "registry", "smss.exe", "csrss.exe",
                "wininit.exe", "services.exe", "lsass.exe",
            }
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    n = (proc.info["name"] or "").lower()
                    if n in SKIP:
                        continue
                    h = k32.OpenProcess(0x0100, False, proc.info["pid"])
                    if h:
                        k32.SetProcessWorkingSetSize(h, ctypes.c_size_t(-1), ctypes.c_size_t(-1))
                        k32.CloseHandle(h)
                except:
                    pass
        except:
            pass
    ok()

def power():
    step("Boosting CPU and power plan")
    HP = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    run(f"powercfg /setactive {HP}", timeout=8)
    run(f"powercfg -duplicatescheme {HP}", timeout=8)
    run(f"powercfg /setactive {HP}", timeout=8)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_USB USBSELECTIVESUSPEND 0",         timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100",     timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100",     timeout=6)
    run("powercfg -h off", timeout=6)
    ok()

def gaming():
    step("Applying gaming tweaks")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR]\r\n"
        '"AppCaptureEnabled"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR]\r\n"
        '"AllowGameDVR"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\System\\GameConfigStore]\r\n"
        '"GameDVR_Enabled"=dword:00000000\r\n'
        '"GameDVR_FSEBehaviorMode"=dword:00000002\r\n'
        '"GameDVR_DXGIHonorFSEWindowsCompatible"=dword:00000001\r\n'
        '"GameDVR_HonorUserFSEBehaviorMode"=dword:00000001\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\GameBar]\r\n"
        '"AutoGameModeEnabled"=dword:00000001\r\n'
        '"AllowAutoGameMode"=dword:00000001\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers]\r\n"
        '"HwSchMode"=dword:00000002\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl]\r\n"
        '"Win32PrioritySeparation"=dword:00000026\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile]\r\n"
        '"NetworkThrottlingIndex"=dword:ffffffff\r\n'
        '"SystemResponsiveness"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games]\r\n"
        '"GPU Priority"=dword:00000008\r\n'
        '"Priority"=dword:00000006\r\n'
        '"Affinity"=dword:00000000\r\n'
        '"Scheduling Category"="High"\r\n'
        '"SFIO Priority"="High"\r\n'
        '"Background Only"="False"\r\n'
        "\r\n"
    )
    ok()

def gpudrv():
    step("Optimizing GPU")
    r, out = rout(
        "nvidia-smi --query-gpu=name --format=csv,noheader,nounits",
        timeout=5
    )
    if r and out:
        name = out.upper()
        gen = 0
        if any(x in name for x in ["1050","1060","1070","1080","1650","1660"]):
            gen = 10
        elif any(x in name for x in ["2050","2060","2070","2080"]):
            gen = 20
        elif any(x in name for x in ["3050","3060","3070","3080","3090"]):
            gen = 30
        elif any(x in name for x in ["4060","4070","4080","4090"]):
            gen = 40
        run("nvidia-smi --auto-boost-default=0", timeout=6)
        if gen >= 20:
            run("nvidia-smi --persistence-mode=1", timeout=6)
    gd = r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
    for name, val in [("HwSchMode", 2), ("TdrDelay", 10), ("TdrDdiDelay", 10)]:
        run(f'reg add "{gd}" /v {name} /t REG_DWORD /d {val} /f', timeout=5)
    ok()

def visual():
    step("Removing animations and visual effects")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects]\r\n"
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
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced]\r\n"
        '"TaskbarAnimations"=dword:00000000\r\n'
        '"ListviewShadow"=dword:00000000\r\n'
        '"ListviewAlphaSelect"=dword:00000000\r\n'
        '"ExtendedUIHoverTime"=dword:00000001\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\DWM]\r\n"
        '"EnableAeroPeek"=dword:00000000\r\n'
        '"AlwaysHibernateThumbnails"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize]\r\n"
        '"EnableTransparency"=dword:00000000\r\n'
        "\r\n"
    )
    try:
        class ANIMATIONINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("iMinAnimate", ctypes.c_int)]
        ai = ANIMATIONINFO()
        ai.cbSize = ctypes.sizeof(ANIMATIONINFO)
        ai.iMinAnimate = 0
        ctypes.windll.user32.SystemParametersInfoW(
            0x0048, ctypes.sizeof(ANIMATIONINFO), ctypes.byref(ai), 3
        )
    except:
        pass
    ok()

def startup():
    step("Cleaning startup programs")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"
        '"OneDrive"=-\r\n'
        '"Skype"=-\r\n'
        '"Teams"=-\r\n'
        '"MicrosoftEdgeUpdate"=-\r\n'
        '"Spotify"=-\r\n'
        '"EpicGamesLauncher"=-\r\n'
        '"SteamClient"=-\r\n'
        '"YourPhone"=-\r\n'
        '"PhoneExperienceHost"=-\r\n'
        '"Discord"=-\r\n'
        '"AdobeUpdater"=-\r\n'
        '"CCleaner"=-\r\n'
        '"Dropbox"=-\r\n'
        '"GoogleDrive"=-\r\n'
        '"Cortana"=-\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"
        '"OneDrive"=-\r\n'
        '"MicrosoftEdgeUpdate"=-\r\n'
        '"EpicGamesLauncher"=-\r\n'
        '"Teams"=-\r\n'
        '"Cortana"=-\r\n'
        "\r\n"
    )
    for t in [
        "OneDrive",
        "MicrosoftEdgeUpdateTaskMachineCore",
        "MicrosoftEdgeUpdateTaskMachineUA",
        "GoogleUpdateTaskMachineCore",
        "GoogleUpdateTaskMachineUA",
    ]:
        run(f'schtasks /Change /TN "{t}" /Disable', timeout=4)
    ok()

def telem():
    step("Disabling telemetry")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection]\r\n"
        '"AllowTelemetry"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection]\r\n"
        '"AllowTelemetry"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Privacy]\r\n"
        '"TailoredExperiencesWithDiagnosticDataEnabled"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo]\r\n"
        '"DisabledByGroupPolicy"=dword:00000001\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo]\r\n"
        '"Enabled"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent]\r\n"
        '"DisableTailoredExperiencesWithDiagnosticData"=dword:00000001\r\n'
        '"DisableWindowsConsumerFeatures"=dword:00000001\r\n'
        '"DisableCloudOptimizedContent"=dword:00000001\r\n'
        "\r\n"
    )
    svcoff(["DiagTrack", "dmwappushservice", "WerSvc", "PcaSvc"])
    ok()

def storage():
    step("Optimizing storage")
    ps_detect = (
        "try { "
        "$disk = (Get-Partition -DriveLetter C -ErrorAction Stop).DiskNumber; "
        "(Get-PhysicalDisk | Where-Object DeviceId -eq $disk).MediaType "
        "} catch { 'Unknown' }"
    )
    r, out = rout(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_detect],
        timeout=10
    )
    dtype = out.strip().upper() if ok else ""
    if "SSD" in dtype or "NVM" in dtype:
        run("fsutil behavior set DisableDeleteNotify 0",                                      timeout=5)
        run("fsutil behavior set disable8dot3 1",                                             timeout=5)
        run("fsutil behavior set encryptpagingfile 0",                                        timeout=5)
        run('schtasks /Change /TN "Microsoft\\Windows\\Defrag\\ScheduledDefrag" /Disable',   timeout=5)
        svcoff(["SysMain"])
    else:
        run("sc config SysMain start= auto", timeout=5)
        run("sc start SysMain",              timeout=5)
    ok()

def svcs():
    step("Disabling unnecessary services")
    svcoff([
        "Fax", "WMPNetworkSvc", "RemoteRegistry", "MapsBroker", "PhoneSvc",
        "XblGameSave", "XblAuthManager", "lfsvc", "wisvc", "TabletInputService",
        "WbioSrvc", "icssvc", "RetailDemo", "DusmSvc", "WalletService",
        "MessagingService", "PimIndexMaintenanceSvc", "OneSyncSvc",
        "UnistoreSvc", "UserDataSvc", "diagsvc", "wercplsupport",
    ])
    ok()

def beast():
    step("Applying beast mode tweaks")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\FileSystem]\r\n"
        '"NtfsDisableLastAccessUpdate"=dword:00000001\r\n'
        '"NtfsMemoryUsage"=dword:00000002\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Control Panel\\Desktop]\r\n"
        '"AutoEndTasks"="1"\r\n'
        '"HungAppTimeout"="1000"\r\n'
        '"WaitToKillAppTimeout"="2000"\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control]\r\n"
        '"WaitToKillServiceTimeout"="2000"\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters]\r\n"
        '"IRPStackSize"=dword:00000014\r\n'
        '"SizReqBuf"=dword:00004000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager]\r\n"
        '"HeapDeCommitFreeBlockThreshold"=dword:00040000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\csrss.exe\\PerfOptions]\r\n"
        '"CpuPriorityClass"=dword:00000004\r\n'
        '"IoPriority"=dword:00000003\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl]\r\n"
        '"IRQ8Priority"=dword:00000001\r\n'
        '"IRQ16Priority"=dword:00000001\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications]\r\n"
        '"GlobalUserDisabled"=dword:00000001\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization]\r\n"
        '"DODownloadMode"=dword:00000000\r\n'
        "\r\n"
    )
    ok()

def netboost():
    step("Boosting network")
    run("ipconfig /flushdns",                                   timeout=5)
    run("netsh int tcp set global autotuninglevel=normal",      timeout=6)
    run("netsh int tcp set global chimney=disabled",            timeout=6)
    run("netsh int tcp set global rss=enabled",                 timeout=6)
    run("netsh int tcp set global netdma=enabled",              timeout=6)
    r, out = rout(
        r'reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"',
        timeout=6
    )
    if r and out:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("HKEY"):
                run(f'reg add "{line}" /v TcpAckFrequency /t REG_DWORD /d 1 /f', timeout=4)
                run(f'reg add "{line}" /v TCPNoDelay      /t REG_DWORD /d 1 /f', timeout=4)
                run(f'reg add "{line}" /v TcpDelAckTicks  /t REG_DWORD /d 0 /f', timeout=4)
    ok()

def procs():
    step("Boosting game processes")
    if not HAS_PSUTIL:
        ok()
        return
    targets = {
        "cs2.exe","csgo.exe","valorant.exe","fortnite.exe","r5apex.exe",
        "eldenring.exe","witcher3.exe","cyberpunk2077.exe","rainbowsix.exe",
        "overwatch.exe","gta5.exe","rocketleague.exe","minecraft.exe","javaw.exe",
        "tslgame.exe","bf4.exe","bf2042.exe","destiny2.exe","cod.exe",
        "warzone.exe","escapefromtarkov.exe","halo_infinite.exe",
        "starfield.exe","dota2.exe","leagueclient.exe",
    }
    n = 0
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pname = proc.info["name"]
            if pname and pname.lower() in targets:
                proc.nice(psutil.HIGH_PRIORITY_CLASS)
                n += 1
        except:
            pass
    ok()
    if n:
        print(f"    {n} game process(es) boosted")

def flush():
    step("Flushing network caches")
    run("ipconfig /flushdns",    timeout=5)
    run("arp -d *",              timeout=5)
    run("nbtstat -R",            timeout=6)
    run("nbtstat -RR",           timeout=6)
    run("ipconfig /registerdns", timeout=6)
    ps("Clear-DnsClientCache -ErrorAction SilentlyContinue", timeout=8)
    ok()

def tcpopt():
    step("Optimizing TCP/IP stack")
    for c in [
        "netsh int tcp set global autotuninglevel=highlyrestricted",
        "netsh int tcp set global congestionprovider=ctcp",
        "netsh int tcp set global ecncapability=enabled",
        "netsh int tcp set global timestamps=disabled",
        "netsh int tcp set global rss=enabled",
        "netsh int tcp set global rsc=enabled",
        "netsh int tcp set global chimney=disabled",
        "netsh int tcp set global netdma=enabled",
        "netsh int tcp set global dca=enabled",
        "netsh int udp set global uro=enabled",
    ]:
        run(c, timeout=6)
    tcp = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    for name, val in [
        ("TcpTimedWaitDelay",         30),
        ("MaxUserPort",               65534),
        ("TcpMaxDataRetransmissions", 5),
        ("DefaultTTL",                64),
        ("EnablePMTUDiscovery",       1),
        ("Tcp1323Opts",               1),
        ("SackOpts",                  1),
        ("TcpMaxDupAcks",             2),
        ("GlobalMaxTcpWindowSize",    8388608),
        ("TcpWindowSize",             8388608),
        ("NumTcbTablePartitions",     4),
        ("MaxFreeTcbs",               65536),
        ("MaxHashTableSize",          65536),
    ]:
        run(f'reg add "{tcp}" /v "{name}" /t REG_DWORD /d {val} /f', timeout=4)
    ok()

def adapters():
    step("Tuning network adapters")
    r, out = rout(
        r'reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"',
        timeout=6
    )
    if r and out:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("HKEY"):
                run(f'reg add "{line}" /v TcpAckFrequency /t REG_DWORD /d 1 /f', timeout=4)
                run(f'reg add "{line}" /v TCPNoDelay      /t REG_DWORD /d 1 /f', timeout=4)
                run(f'reg add "{line}" /v TcpDelAckTicks  /t REG_DWORD /d 0 /f', timeout=4)
                run(f'reg add "{line}" /v TcpInitialRTT   /t REG_DWORD /d 3 /f', timeout=4)
    ok()

def wifi():
    step("Optimizing WiFi")
    adapters = wifiadp()
    for adapter in adapters:
        safe = adapter.replace("'","").replace('"',"")
        for kw, val in [
            ("RoamAggressiveness",   "1"),
            ("*TransmitBuffers",     "1024"),
            ("*ReceiveBuffers",      "1024"),
            ("*InterruptModeration", "0"),
        ]:
            ps(
                f"Set-NetAdapterAdvancedProperty -Name '{safe}' "
                f"-RegistryKeyword '{kw}' -RegistryValue {val} -ErrorAction SilentlyContinue",
                timeout=8
            )
        ps(
            f"Disable-NetAdapterPowerManagement -Name '{safe}' -ErrorAction SilentlyContinue",
            timeout=8
        )
    run(
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" '
        r'/v fMinimizeConnections /t REG_DWORD /d 0 /f',
        timeout=4
    )
    run("netsh wlan set profileparameter mode=auto", timeout=5)
    ok()

def dns():
    step("Finding fastest DNS")
    DNS = [
        ("Cloudflare", "1.1.1.1",       "1.0.0.1"),
        ("Google",     "8.8.8.8",        "8.8.4.4"),
        ("Quad9",      "9.9.9.9",        "149.112.112.112"),
        ("OpenDNS",    "208.67.222.222", "208.67.220.220"),
        ("AdGuard",    "94.140.14.14",   "94.140.15.15"),
    ]
    best_name, best_pri, best_sec, best_ms = "Cloudflare", "1.1.1.1", "1.0.0.1", 9999
    for name, pri, sec in DNS:
        ms = pingms(pri)
        if ms is not None and ms < best_ms:
            best_ms, best_name, best_pri, best_sec = ms, name, pri, sec
    for iface in alladp():
        run(f'netsh interface ip set dns name="{iface}" static {best_pri} primary', timeout=6)
        run(f'netsh interface ip add dns name="{iface}" {best_sec} index=2',        timeout=6)
    run("ipconfig /flushdns", timeout=5)
    ok()
    print(f"    Best DNS: {best_name} ({best_pri}) at {best_ms}ms")

def qos():
    step("Removing bandwidth limits")
    run(
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" '
        r'/v NonBestEffortLimit /t REG_DWORD /d 0 /f',
        timeout=4
    )
    run(
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" '
        r'/v "Do not use NLA" /t REG_SZ /d "1" /f',
        timeout=4
    )
    run(
        r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" '
        r'/v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f',
        timeout=4
    )
    run("netsh int ip set global taskoffload=enabled",      timeout=6)
    run("netsh int ip set global neighborcachelimit=4096",  timeout=6)
    run("netsh int ip set global routecachelimit=4096",     timeout=6)
    ok()

def netreset():
    step("Resetting network stack")
    run("netsh winsock reset", timeout=10)
    run("netsh int ip reset",  timeout=10)
    run("netsh int tcp reset", timeout=8)
    run("netsh int ipv6 reset",timeout=8)
    run("ipconfig /release",   timeout=12)
    run("ipconfig /renew",     timeout=18)
    run("ipconfig /flushdns",  timeout=5)
    ok()

def mtu():
    step("Setting optimal MTU for all adapters")
    ifaces = alladp()
    tuned = 0
    for iface in ifaces:
        try:
            r, out = rout(f'netsh interface ipv4 show subinterface "{iface}"', timeout=5)
            current = None
            if r and out:
                for line in out.splitlines():
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        try: current = int(parts[0])
                        except: pass
            if current != 1500:
                run(f'netsh interface ipv4 set subinterface "{iface}" mtu=1500 store=persistent', timeout=6)
                run(f'netsh interface ipv6 set subinterface "{iface}" mtu=1500 store=persistent', timeout=6)
            tuned += 1
        except:
            pass
    ps(
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { "
        "  $n = $_.InterfaceAlias; "
        "  try { netsh interface ipv4 set subinterface $n mtu=1500 store=persistent 2>$null } catch {}; "
        "  try { netsh interface ipv6 set subinterface $n mtu=1500 store=persistent 2>$null } catch {} "
        "}",
        timeout=20
    )
    ok()
    if tuned:
        print(f"    {tuned} adapter(s) set to MTU 1500")

def ethernet():
    step("Optimizing Ethernet adapters")
    ps(
        "Get-NetAdapter | Where-Object { $_.MediaType -eq '802.3' -and $_.Status -eq 'Up' } | ForEach-Object { "
        "  $n = $_.Name; "
        "  try { Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*SpeedDuplex' -RegistryValue 0 -ErrorAction SilentlyContinue } catch {}; "
        "  try { Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*EEE' -RegistryValue 0 -ErrorAction SilentlyContinue } catch {}; "
        "  try { Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword 'EnableGreenEthernet' -RegistryValue 0 -ErrorAction SilentlyContinue } catch {}; "
        "  try { Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*WakeOnMagicPacket' -RegistryValue 0 -ErrorAction SilentlyContinue } catch {}; "
        "  try { Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*WakeOnPattern' -RegistryValue 0 -ErrorAction SilentlyContinue } catch {}; "
        "  try { Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*LsoV2IPv4' -RegistryValue 1 -ErrorAction SilentlyContinue } catch {}; "
        "  try { Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*LsoV2IPv6' -RegistryValue 1 -ErrorAction SilentlyContinue } catch {}; "
        "  try { Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*InterruptModeration' -RegistryValue 0 -ErrorAction SilentlyContinue } catch {}; "
        "  try { Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*TransmitBuffers' -RegistryValue 1024 -ErrorAction SilentlyContinue } catch {}; "
        "  try { Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*ReceiveBuffers' -RegistryValue 1024 -ErrorAction SilentlyContinue } catch {}; "
        "  try { Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*FlowControl' -RegistryValue 0 -ErrorAction SilentlyContinue } catch {}; "
        "  try { Disable-NetAdapterPowerManagement -Name $n -ErrorAction SilentlyContinue } catch {} "
        "}",
        timeout=25
    )
    ok()

def gcache():
    step("Clearing GPU shader/cache files")
    lad = os.environ.get("LOCALAPPDATA", "")
    dirs = [
        os.path.join(lad, "NVIDIA", "DXCache"),
        os.path.join(lad, "NVIDIA", "GLCache"),
        os.path.join(lad, "NVIDIA", "OptixCache"),
        os.path.join(lad, "D3DSCache"),
        os.path.join(lad, "AMD", "DxCache"),
        os.path.join(lad, "AMD", "DxcCache"),
        os.path.join(lad, "Intel", "ShaderCache"),
        os.path.join(lad, "Google",        "Chrome",        "User Data", "Default", "GPUCache"),
        os.path.join(lad, "Microsoft",     "Edge",          "User Data", "Default", "GPUCache"),
        os.path.join(lad, "BraveSoftware", "Brave-Browser", "User Data", "Default", "GPUCache"),
        os.path.join(lad, "Temp"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
    ]
    wiped = 0
    for d in dirs:
        if d and os.path.isdir(d):
            try:
                before = sum(1 for _ in Path(d).rglob("*") if Path(_).is_file())
                wipe(d)
                wiped += before
            except:
                wipe(d)
    ok()
    if wiped:
        print(f"    ~{wiped} cache files cleared")

def greg():
    step("Applying GPU registry tweaks")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers]\r\n"
        '"HwSchMode"=dword:00000002\r\n'
        '"TdrDelay"=dword:0000000a\r\n'
        '"TdrDdiDelay"=dword:0000000a\r\n'
        '"TdrLevel"=dword:00000003\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games]\r\n"
        '"GPU Priority"=dword:00000008\r\n'
        '"Priority"=dword:00000006\r\n'
        '"Scheduling Category"="High"\r\n'
        '"SFIO Priority"="High"\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000]\r\n"
        '"EnableUlps"=dword:00000000\r\n'
        "\r\n"
    )
    ok()

def gnvidia():
    step("Tuning NVIDIA settings")
    r, out = rout("nvidia-smi --query-gpu=name --format=csv,noheader,nounits", timeout=5)
    if not (r and out):
        ok()
        print("    No NVIDIA GPU detected, skipping")
        return
    run("nvidia-smi --auto-boost-default=0",   timeout=6)
    run("nvidia-smi --persistence-mode=1",     timeout=6)
    run("nvidia-smi --gpu-reset-ecc-errors=0", timeout=6)
    run(
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" '
        r'/v "RMHdcpKeygroupSize" /t REG_DWORD /d 4 /f',
        timeout=4
    )
    run(
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" '
        r'/v "EnableMidBufferPreemption" /t REG_DWORD /d 0 /f',
        timeout=4
    )
    run(
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" '
        r'/v "EnableCEPreemption" /t REG_DWORD /d 0 /f',
        timeout=4
    )
    ok()
    print(f"    NVIDIA GPU: {out.strip()}")

def gamd():
    step("Tuning AMD settings")
    r, out = rout("wmic path win32_VideoController get name", timeout=6)
    if not (r and ("AMD" in out.upper() or "RADEON" in out.upper())):
        ok()
        print("    No AMD GPU detected, skipping")
        return
    run(
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" '
        r'/v "EnableUlps" /t REG_DWORD /d 0 /f',
        timeout=4
    )
    run(
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" '
        r'/v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d 0 /f',
        timeout=4
    )
    run(
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" '
        r'/v "DisableDMACopy" /t REG_DWORD /d 1 /f',
        timeout=4
    )
    ok()

def grefresh():
    step("Refreshing GPU display driver (Ctrl+Shift+Win+B)")
    try:
        VK_B            = 0x42
        VK_CONTROL      = 0x11
        VK_SHIFT        = 0x10
        VK_LWIN         = 0x5B
        KEYEVENTF_KEYUP = 0x0002
        u32 = ctypes.windll.user32
        keys_down = [VK_CONTROL, VK_SHIFT, VK_LWIN, VK_B]
        for k in keys_down:
            u32.keybd_event(k, 0, 0, 0)
            time.sleep(0.05)
        time.sleep(0.1)
        for k in reversed(keys_down):
            u32.keybd_event(k, 0, KEYEVENTF_KEYUP, 0)
            time.sleep(0.05)
        time.sleep(2)
        ok()
    except Exception as e:
        ok()
        print(f"    keybd_event failed: {e}")

def gvram():
    step("Flushing standby memory / VRAM pressure")
    try:
        if HAS_PSUTIL:
            k32 = ctypes.windll.kernel32
            SKIP = {"system","registry","smss.exe","csrss.exe","wininit.exe","services.exe","lsass.exe"}
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    n = (proc.info["name"] or "").lower()
                    if n in SKIP:
                        continue
                    h = k32.OpenProcess(0x0100, False, proc.info["pid"])
                    if h:
                        k32.SetProcessWorkingSetSize(h, ctypes.c_size_t(-1), ctypes.c_size_t(-1))
                        k32.CloseHandle(h)
                except:
                    pass
        ps("[GC]::Collect(); [GC]::WaitForPendingFinalizers()", timeout=8)
    except:
        pass
    ok()

def gdx():
    step("Refreshing DirectX and GPU info")
    run("dxdiag /whql:off /t %TEMP%\\dxinfo.txt", timeout=30)
    tmp = os.path.join(os.environ.get("TEMP",""), "dxinfo.txt")
    try:
        os.unlink(tmp)
    except:
        pass
    ok()

def gpow():
    step("Setting GPU to max performance power state")
    HP = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    run(f"powercfg /setactive {HP}",                                       timeout=8)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 0",  timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO DEVICEIDLE 0", timeout=6)
    ok()

def gsched():
    step("Optimizing GPU task scheduling")
    run(
        r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" '
        r'/v "GPU Priority" /t REG_DWORD /d 8 /f',
        timeout=4
    )
    run(
        r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" '
        r'/v "Priority" /t REG_DWORD /d 6 /f',
        timeout=4
    )
    run(
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" '
        r'/v "EnablePreemption" /t REG_DWORD /d 1 /f',
        timeout=4
    )
    ok()

def dpower():
    step("Disabling display power saving")
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 0",    timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO ADAPTBRIGHT 0",  timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO ALLOWSTANDBY 0", timeout=6)
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_CURRENT_USER\\Control Panel\\Desktop]\r\n"
        '"ScreenSaveActive"="0"\r\n'
        '"ScreenSaverIsSecure"="0"\r\n'
        "\r\n"
    )
    ok()

def drender():
    step("Optimizing display rendering pipeline")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers]\r\n"
        '"HwSchMode"=dword:00000002\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Dwm]\r\n"
        '"Composition"=dword:00000001\r\n'
        '"DisableHWAcceleration"=dword:00000000\r\n'
        '"OverlayTestMode"=dword:00000005\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\DWM]\r\n"
        '"EnableAeroPeek"=dword:00000000\r\n'
        '"AlwaysHibernateThumbnails"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile]\r\n"
        '"SystemResponsiveness"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\System\\GameConfigStore]\r\n"
        '"GameDVR_FSEBehavior"=dword:00000002\r\n'
        '"GameDVR_DXGIHonorFSEWindowsCompatible"=dword:00000001\r\n'
        '"GameDVR_EFSEFeatureFlags"=dword:00000000\r\n'
        "\r\n"
    )
    ok()

def drefresh():
    step("Setting highest available refresh rate")
    ps(
        "Add-Type -TypeDefinition @\"\r\n"
        "using System; using System.Runtime.InteropServices;\r\n"
        "public class D {\r\n"
        "  [DllImport(\"user32.dll\")] public static extern bool EnumDisplaySettings(string d,int m,ref DM dm);\r\n"
        "  [DllImport(\"user32.dll\")] public static extern int ChangeDisplaySettings(ref DM dm,int f);\r\n"
        "  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Ansi)] public struct DM {\r\n"
        "    [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)] public string n;\r\n"
        "    public short sv,dv,ds,de; public int fi,px,py,dor,dfo;\r\n"
        "    public short dc,dd,yr,tto,cl; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)] public string fn;\r\n"
        "    public short lp; public int bp,pw,ph,df,freq;\r\n"
        "  }\r\n"
        "}\r\n"
        "\"@ -ErrorAction SilentlyContinue;\r\n"
        "try {\r\n"
        "  $dm=New-Object D+DM; $dm.ds=[System.Runtime.InteropServices.Marshal]::SizeOf($dm);\r\n"
        "  [D]::EnumDisplaySettings($null,-1,[ref]$dm)|Out-Null;\r\n"
        "  foreach($r in @(360,240,165,144,120,100,75,60)){\r\n"
        "    $dm.freq=$r; $dm.fi=0x400000;\r\n"
        "    if([D]::ChangeDisplaySettings([ref]$dm,1) -eq 0){Write-Host \"Set to $($r)Hz\"; break}\r\n"
        "  }\r\n"
        "} catch {}",
        timeout=15
    )
    ok()

def dcolor():
    step("Optimizing display color settings")
    ps(
        "try { "
        "  Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CloudStore\\Store\\DefaultAccount\\Current\\default$windows.data.bluelightreduction.settings\\windows.data.bluelightreduction.settings' "
        "  -Name 'Data' -Type Binary -Value ([byte[]](0x43,0x42,0x01,0x00,0xC4,0x0A,0x00,0x00,0x00,0x00)) -ErrorAction SilentlyContinue "
        "} catch {}",
        timeout=8
    )
    ok()

def dfonts():
    step("Enabling ClearType and font smoothing")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_CURRENT_USER\\Control Panel\\Desktop]\r\n"
        '"FontSmoothing"="2"\r\n'
        '"FontSmoothingType"=dword:00000002\r\n'
        '"FontSmoothingGamma"=dword:00000578\r\n'
        '"FontSmoothingOrientation"=dword:00000001\r\n'
        "\r\n"
    )
    ok()

def dscaling():
    step("Setting best display scaling (100% DPI)")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_CURRENT_USER\\Control Panel\\Desktop]\r\n"
        '"LogPixels"=dword:00000060\r\n'
        '"Win8DpiScaling"=dword:00000001\r\n'
        "\r\n"
    )
    ps(
        "try { Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'DPIOverride' -Value -1 -ErrorAction SilentlyContinue } catch {}",
        timeout=8
    )
    ok()

def dhdr():
    step("Enabling HDR for capable displays")
    ps(
        "try { "
        "  Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\VideoSettings' "
        "  -Name 'EnableHDRForPlayback' -Value 1 -ErrorAction SilentlyContinue "
        "} catch {}",
        timeout=8
    )
    ok()

def dgpu_disp():
    step("Setting GPU display output preferences")
    if nvcheck():
        run(
            r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" '
            r'/v "D3PCLatency" /t REG_DWORD /d 1 /f',
            timeout=4
        )
    if amdcheck():
        run(
            r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" '
            r'/v "VSyncControl" /t REG_DWORD /d 0 /f',
            timeout=4
        )
    ok()

def gsvcs():
    step("Disabling background services for gaming")
    svcoff([
        "DiagTrack", "dmwappushservice", "WerSvc", "PcaSvc",
        "SysMain", "TabletInputService", "WSearch",
        "XblGameSave", "XblAuthManager",
        "MapsBroker", "PhoneSvc", "RetailDemo",
        "WMPNetworkSvc", "icssvc", "lfsvc",
        "DusmSvc", "WalletService", "MessagingService",
        "OneSyncSvc", "UnistoreSvc", "UserDataSvc",
        "RemoteRegistry", "Fax",
    ])
    ps(
        "Get-ScheduledTask | Where-Object {"
        "  $_.State -eq 'Ready' -and ("
        "    $_.TaskName -like '*Update*' -or "
        "    $_.TaskName -like '*Telemetry*' -or "
        "    $_.TaskName -like '*Feedback*' -or "
        "    $_.TaskName -like '*Maintenance*'"
        "  )"
        "} | Disable-ScheduledTask -ErrorAction SilentlyContinue",
        timeout=15
    )
    ok()

def gkill():
    step("Closing background apps (keeping Discord + recorders)")
    if not HAS_PSUTIL:
        ok()
        return
    keep = {
        "discord.exe","discordptb.exe","discordcanary.exe",
        "obs64.exe","obs32.exe","obs.exe",
        "streamlabs obs.exe","slobs.exe",
        "xsplit.core.exe","xsplitbroadcaster.exe",
        "nvsphelper64.exe","nvcontainer.exe",
        "medal.exe","outplayed.exe","plays.exe",
        "overwolf.exe",
        "system","registry","smss.exe","csrss.exe",
        "wininit.exe","winlogon.exe","services.exe","lsass.exe",
        "svchost.exe","dwm.exe","explorer.exe",
        "taskmgr.exe","pythonw.exe","python.exe",
        "conhost.exe","cmd.exe",
    }
    kill_targets = {
        "msedge.exe","microsoftedge.exe","chrome.exe","firefox.exe","brave.exe",
        "opera.exe","vivaldi.exe",
        "onedrive.exe","onedrivesetup.exe",
        "skype.exe","skypeapp.exe",
        "teams.exe","ms-teams.exe",
        "spotify.exe",
        "steam.exe","steamwebhelper.exe",
        "epicgameslauncher.exe",
        "origin.exe","eadesktop.exe",
        "upc.exe","slack.exe","zoom.exe",
        "microsoftedgeupdate.exe",
        "searchindexer.exe","searchapp.exe",
        "cortana.exe",
        "yourphone.exe","phoneexperiencehost.exe",
        "gamebar.exe","gamebarftserver.exe",
        "widgets.exe","widgetservice.exe",
        "xboxapp.exe","xboxgameoverlay.exe",
        "tabtip.exe","tabtip32.exe",
        "winstore.app.exe",
        "acrobat.exe","acrord32.exe",
        "vlc.exe","mspaint.exe","notepad.exe",
    }
    killed = 0
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pname = (proc.info["name"] or "").lower()
            if pname in keep:
                continue
            if pname in kill_targets:
                proc.kill()
                killed += 1
        except:
            pass
    ok()
    print(f"    {killed} apps closed")

def gram():
    step("Turbo RAM flush for gaming")
    if not HAS_PSUTIL:
        ok()
        return
    before = gb(psutil.virtual_memory().available)
    game_procs = {
        "cs2.exe","csgo.exe","valorant.exe","fortnite.exe","r5apex.exe",
        "eldenring.exe","witcher3.exe","cyberpunk2077.exe","rainbowsix.exe",
        "overwatch.exe","gta5.exe","rocketleague.exe","minecraft.exe","javaw.exe",
        "tslgame.exe","bf4.exe","bf2042.exe","destiny2.exe","cod.exe",
        "warzone.exe","escapefromtarkov.exe","halo_infinite.exe",
        "starfield.exe","dota2.exe","leagueclient.exe",
    }
    SKIP = {"system","registry","smss.exe","csrss.exe","wininit.exe","services.exe","lsass.exe"}
    try:
        k32 = ctypes.windll.kernel32
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pname = (proc.info["name"] or "").lower()
                if pname in SKIP or pname in game_procs:
                    continue
                h = k32.OpenProcess(0x0100, False, proc.info["pid"])
                if h:
                    k32.SetProcessWorkingSetSize(h, ctypes.c_size_t(-1), ctypes.c_size_t(-1))
                    k32.CloseHandle(h)
            except:
                pass
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pname = (proc.info["name"] or "").lower()
                if pname in game_procs:
                    proc.nice(psutil.HIGH_PRIORITY_CLASS)
                    try:
                        proc.ionice(psutil.IOPRIO_HIGH)
                    except:
                        pass
            except:
                pass
    except:
        pass
    ps("[GC]::Collect(2,[System.GCCollectionMode]::Forced,$true,$true);[GC]::WaitForPendingFinalizers()", timeout=10)
    ok()
    after = gb(psutil.virtual_memory().available)
    gained = round(after - before, 1)
    ok()
    print(f"    +{gained} GB freed  ({after} GB now available)")

def gcpu():
    step("Setting CPU to max gaming priority")
    HP = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    run(f"powercfg /setactive {HP}",                                                   timeout=8)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100",  timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100",  timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 2",      timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 1",        timeout=6)
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games]\r\n"
        '"GPU Priority"=dword:00000008\r\n'
        '"Priority"=dword:00000006\r\n'
        '"Scheduling Category"="High"\r\n'
        '"SFIO Priority"="High"\r\n'
        '"Background Only"="False"\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl]\r\n"
        '"Win32PrioritySeparation"=dword:00000026\r\n'
        "\r\n"
    )
    ok()

def gnet():
    step("Prioritizing game network traffic")
    run(
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" '
        r'/v NonBestEffortLimit /t REG_DWORD /d 0 /f',
        timeout=4
    )
    run(
        r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" '
        r'/v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f',
        timeout=4
    )
    run("netsh int tcp set global autotuninglevel=highlyrestricted", timeout=6)
    run("netsh int tcp set global rss=enabled",                      timeout=6)
    run("ipconfig /flushdns",                                        timeout=5)
    ok()

def scanapps():
    found = {}
    lad = os.environ.get("LOCALAPPDATA", "")
    pf  = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86= os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    apd = os.environ.get("APPDATA", "")

    r, out = rout(
        'powershell -NoProfile -NonInteractive -Command '
        '"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,'
        'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,'
        'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* '
        '| Where-Object { $_.DisplayName } '
        '| Select-Object DisplayName,InstallLocation,UninstallString '
        '| ConvertTo-Csv -NoTypeInformation"',
        timeout=20
    )
    if r and out:
        lines = out.splitlines()
        for line in lines[1:]:
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 1 and parts[0]:
                name = parts[0].strip()
                loc  = parts[1].strip() if len(parts) > 1 else ""
                unin = parts[2].strip() if len(parts) > 2 else ""
                if name and name not in found:
                    found[name] = {"loc": loc, "uninstall": unin}

    uwp_script = (
        "Get-AppxPackage | Where-Object { $_.SignatureKind -ne 'System' } "
        "| Select-Object Name,InstallLocation | ConvertTo-Csv -NoTypeInformation"
    )
    r2, out2 = rout(
        f'powershell -NoProfile -NonInteractive -Command "{uwp_script}"',
        timeout=20
    )
    if r2 and out2:
        for line in out2.splitlines()[1:]:
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 1 and parts[0]:
                name = parts[0].strip()
                loc  = parts[1].strip() if len(parts) > 1 else ""
                tag  = name + "  [UWP]"
                if tag not in found:
                    found[tag] = {"loc": loc, "uninstall": "uwp"}

    return found


def checkapp(name, info):
    issues = []
    loc = info.get("loc", "")

    if loc and not os.path.isdir(loc):
        issues.append("install folder missing")

    if loc and os.path.isdir(loc):
        try:
            exes = list(Path(loc).rglob("*.exe"))
            if not exes:
                issues.append("no executable found in install folder")
        except:
            pass

    lad = os.environ.get("LOCALAPPDATA", "")
    apd = os.environ.get("APPDATA", "")
    n   = name.lower().split("[")[0].strip()

    cache_dirs = [
        os.path.join(lad, n, "Cache"),
        os.path.join(apd, n, "Cache"),
    ]
    for cd in cache_dirs:
        if os.path.isdir(cd):
            try:
                sz = sum(f.stat().st_size for f in Path(cd).rglob("*") if f.is_file())
                if sz > 200 * 1024 * 1024:
                    issues.append(f"large cache ({round(sz/1024/1024)} MB)")
            except:
                pass

    crash_dirs = [
        os.path.join(lad, n, "CrashReports"),
        os.path.join(lad, n, "crashes"),
        os.path.join(lad, "CrashDumps"),
    ]
    for cd in crash_dirs:
        if os.path.isdir(cd):
            try:
                dumps = list(Path(cd).glob("*.dmp"))
                if dumps:
                    issues.append(f"{len(dumps)} crash dump(s) found")
                    break
            except:
                pass

    return issues


def fixapp(name, info):
    n   = name.lower().split("[")[0].strip()
    lad = os.environ.get("LOCALAPPDATA", "")
    apd = os.environ.get("APPDATA", "")
    loc = info.get("loc", "")

    step(f"Clearing cache for {name.split('[')[0].strip()}")
    for base in [lad, apd]:
        for sub in ["Cache", "cache", "Code Cache", "GPUCache", "Temp", "temp", "CrashReports", "crashes"]:
            p = os.path.join(base, n, sub)
            if os.path.isdir(p):
                wipe(p)
    ok()

    if info.get("uninstall") != "uwp" and loc and os.path.isdir(loc):
        step("Re-registering app with Windows")
        run(
            f'powershell -NoProfile -NonInteractive -Command '
            f'"Get-AppxPackage | Where-Object {{ $_.InstallLocation -like \'*{n}*\' }}'
            f' | ForEach-Object {{ Add-AppxPackage -DisableDevelopmentMode -Register \'$($_.InstallLocation)\\AppxManifest.xml\' -ErrorAction SilentlyContinue }}"',
            timeout=15
        )
        ok()

    if info.get("uninstall") == "uwp":
        step("Re-registering UWP package")
        mf = os.path.join(loc, "AppxManifest.xml") if loc else ""
        if mf and os.path.isfile(mf):
            ps(
                f"Add-AppxPackage -DisableDevelopmentMode -Register '{mf}' -ErrorAction SilentlyContinue",
                timeout=15
            )
        ok()

    step("Flushing app event logs")
    run(f'wevtutil cl Application', timeout=6)
    ok()


def autofix():
    print()
    print("  Scanning all installed apps... (this may take a moment)")
    apps = scanapps()
    if not apps:
        print("  No apps found.")
        return

    flagged = {}
    total = len(apps)
    done  = 0
    for name, info in apps.items():
        issues = checkapp(name, info)
        if issues:
            flagged[name] = (info, issues)
        done += 1
        pct = int(done / total * 100)
        print(f"\r  Checking... {pct}%  ({done}/{total})", end="", flush=True)

    print(f"\r  Scan complete. {total} apps checked.              ")
    print()

    if not flagged:
        print("  No issues found across all apps.")
        return

    print(f"  Found issues in {len(flagged)} app(s):\n")
    for name, (info, issues) in flagged.items():
        label = name.split("[")[0].strip()
        print(f"    {label}")
        for iss in issues:
            print(f"      - {iss}")
    print()

    go = input("  Fix all flagged apps now? (y/N): ").strip().lower()
    if go != "y":
        return

    print()
    for name, (info, issues) in flagged.items():
        fixapp(name, info)

    print()
    print("  All flagged apps repaired.")


def pickapp():
    print()
    print("  Scanning installed apps...")
    apps = scanapps()
    if not apps:
        print("  No apps found.")
        return

    names = sorted(apps.keys(), key=lambda x: x.lower())
    print(f"\n  {len(names)} apps found.\n")

    q = input("  Search app name (or press Enter to list all): ").strip().lower()
    if q:
        names = [n for n in names if q in n.lower()]
        if not names:
            print("  No matches found.")
            return

    for i, n in enumerate(names, 1):
        label = n.split("[")[0].strip()
        print(f"  [{i:>3}] {label}" + ("  [UWP]" if "[UWP]" in n else ""))

    print()
    try:
        pick = int(input("  Select app number: ").strip())
        if pick < 1 or pick > len(names):
            print("  Invalid selection.")
            return
    except:
        print("  Invalid input.")
        return

    chosen = names[pick - 1]
    info   = apps[chosen]
    label  = chosen.split("[")[0].strip()

    print(f"\n  Checking {label}...")
    issues = checkapp(chosen, info)

    if not issues:
        print(f"  No issues found with {label}.")
    else:
        print(f"  Issues found:")
        for iss in issues:
            print(f"    - {iss}")

    print()
    go = input(f"  Repair {label} now? (y/N): ").strip().lower()
    if go == "y":
        print()
        fixapp(chosen, info)
        print(f"\n  {label} repaired.")


def sysfix():
    print()
    step("Running SFC scan")
    run("sfc /scannow", timeout=300)
    ok()

    step("Running DISM health restore")
    run("DISM /Online /Cleanup-Image /RestoreHealth", timeout=300)
    ok()

    step("Rebuilding icon cache")
    lad = os.environ.get("LOCALAPPDATA", "")
    ic  = os.path.join(lad, "IconCache.db")
    try:
        if os.path.isfile(ic):
            os.remove(ic)
    except:
        pass
    ok()

    step("Rebuilding font cache")
    run('net stop "Windows Font Cache Service"',                             timeout=8)
    win = os.environ.get("SystemRoot", r"C:\Windows")
    fc  = os.path.join(win, "ServiceProfiles", "LocalService", "AppData", "Local", "FontCache")
    if os.path.isdir(fc):
        wipe(fc)
    run('net start "Windows Font Cache Service"',                            timeout=8)
    ok()

    step("Clearing Windows Store cache")
    run("wsreset.exe", timeout=30)
    ok()

    step("Re-registering all UWP apps")
    ps(
        "Get-AppxPackage | ForEach-Object { "
        "  $mf = Join-Path $_.InstallLocation 'AppxManifest.xml'; "
        "  if (Test-Path $mf) { "
        "    Add-AppxPackage -DisableDevelopmentMode -Register $mf -ErrorAction SilentlyContinue "
        "  } "
        "}",
        timeout=120
    )
    ok()

    step("Fixing broken file associations")
    run(
        r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts" /f',
        timeout=6
    )
    ok()

    step("Clearing thumbnail cache")
    run("cleanmgr /sagerun:1",                                               timeout=60)
    wipe(os.path.join(
        os.environ.get("LOCALAPPDATA", ""),
        "Microsoft", "Windows", "Explorer"
    ))
    ok()

    step("Resetting Windows Update components")
    for svc in ["wuauserv", "cryptSvc", "bits", "msiserver"]:
        run(f"net stop {svc}", timeout=8)
    win = os.environ.get("SystemRoot", r"C:\Windows")
    sd  = os.path.join(win, "SoftwareDistribution")
    cr  = os.path.join(win, "System32", "catroot2")
    if os.path.isdir(sd):
        shutil.rmtree(sd, ignore_errors=True)
    if os.path.isdir(cr):
        shutil.rmtree(cr, ignore_errors=True)
    for svc in ["wuauserv", "cryptSvc", "bits", "msiserver"]:
        run(f"net start {svc}", timeout=8)
    ok()

    step("Flushing DNS and resetting Winsock")
    run("ipconfig /flushdns",  timeout=5)
    run("netsh winsock reset", timeout=10)
    run("netsh int ip reset",  timeout=10)
    ok()

    step("Fixing common registry permissions")
    for key in [
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        r"HKLM\SYSTEM\CurrentControlSet\Services",
    ]:
        run(f'icacls "{key}" /reset /T /Q', timeout=10)
    ok()

    print()
    print("  System issue resolver complete!")
    print("  A restart is recommended to apply all fixes.")


def repairrun():
    print()
    print("  [1] Select app to repair")
    print("  [2] Auto-scan and fix all apps")
    print("  [3] System issue resolver")
    print("  [B] Back")
    print()

    c = input("  Enter: ").strip().upper()

    if c == "1":
        pickapp()
    elif c == "2":
        autofix()
    elif c == "3":
        sysfix()
    elif c == "B":
        return
    else:
        print("  Invalid option.")


def tweaker():
    print()
    bloat()
    temp()
    browsers()
    ram()
    power()
    gaming()
    gpudrv()
    visual()
    startup()
    telem()
    storage()
    svcs()
    beast()
    netboost()
    procs()
    print()
    print("  All done! Restart your PC for full effect.")
    if nvcheck():
        print("  Set NVIDIA Control Panel -> Prefer Maximum Performance.")

def netrun():
    print()
    flush()
    tcpopt()
    mtu()
    adapters()
    ethernet()
    wifi()
    dns()
    qos()
    netreset()
    print()
    print("  Net boost complete! Restart your PC for full effect.")

def gpurun():
    print()
    print("  Detected GPUs:")
    r, out = rout("nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits", timeout=5)
    if r and out:
        for line in out.splitlines():
            parts = [x.strip() for x in line.split(",")]
            if len(parts) >= 2:
                print(f"    NVIDIA: {parts[0]}  ({parts[1]} MB VRAM)")
    r2, out2 = rout("wmic path win32_VideoController get name", timeout=6)
    if r2 and out2:
        for line in out2.splitlines():
            line = line.strip()
            if line and line.lower() != "name" and ("AMD" in line.upper() or "RADEON" in line.upper()):
                print(f"    AMD: {line}")
    print()
    gcache()
    greg()
    gnvidia()
    gamd()
    gpow()
    gsched()
    gvram()
    gdx()
    grefresh()
    print()
    print("  GPU optimization complete!")
    print("  Screen may flicker for 1-2 seconds - that's the driver refresh.")
    if nvcheck():
        print("  Tip: NVIDIA Control Panel -> Manage 3D Settings -> Power: Prefer Max Performance")

def disprun():
    print()
    dpower()
    drender()
    drefresh()
    dcolor()
    dfonts()
    dscaling()
    dhdr()
    dgpu_disp()
    print()
    print("  Display tuning complete!")
    print("  Tip: Display Settings -> Advanced display -> verify your refresh rate is active.")

def fps():
    step("Setting timer resolution to 0.5ms")
    try:
        ntdll = ctypes.windll.ntdll
        ntdll.NtSetTimerResolution(5000, True, ctypes.byref(ctypes.c_ulong()))
    except:
        pass
    run('powershell -NoProfile -NonInteractive -Command "'
        'Add-Type -TypeDefinition \'using System;using System.Runtime.InteropServices;'
        'public class TR{[DllImport("ntdll.dll")]public static extern int NtSetTimerResolution(int dr,bool sr,ref int cr);}\';'
        '[TR]::NtSetTimerResolution(5000,$true,[ref]0)"', timeout=8)
    ok()

    step("Disabling CPU core parking")
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\'
        '54533251-82be-4824-96c1-47b60b740d00\\0cc5b647-c1df-4637-891a-dec35c318583" '
        '/v ValueMax /t REG_DWORD /d 0 /f', timeout=5)
    run('powercfg /SETACVALUEINDEX SCHEME_CURRENT '
        '54533251-82be-4824-96c1-47b60b740d00 '
        '0cc5b647-c1df-4637-891a-dec35c318583 0', timeout=6)
    run('powercfg /SETACVALUEINDEX SCHEME_CURRENT '
        '54533251-82be-4824-96c1-47b60b740d00 '
        'ea062031-0e34-4ff1-9b6d-eb1059334028 100', timeout=6)
    ok()

    step("Disabling CPU heterogeneous scheduling")
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\'
        '54533251-82be-4824-96c1-47b60b740d00\\2bfc2888-f606-4b1b-a9c1-5dfdb0a08c50" '
        '/v ValueMax /t REG_DWORD /d 0 /f', timeout=5)
    ok()

    step("Locking CPU to max frequency")
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100", timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100", timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 2",     timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTPOL 100",    timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PERFEPP 0",           timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 1",       timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR LATENCYHINTPERF1 100",timeout=6)
    ok()

    step("Disabling HPET system timer")
    run("bcdedit /set useplatformclock false",   timeout=6)
    run("bcdedit /set disabledynamictick yes",   timeout=6)
    run("bcdedit /set tscsyncpolicy enhanced",   timeout=6)
    run("bcdedit /set x2apicpolicy enable",      timeout=6)
    ok()

    step("Stripping GPU driver telemetry overhead")
    run('reg add "HKLM\\SOFTWARE\\NVIDIA Corporation\\NvControlPanel2\\Client" '
        '/v OptInOrOutPreference /t REG_DWORD /d 0 /f', timeout=4)
    run('reg add "HKLM\\SOFTWARE\\NVIDIA Corporation\\Global\\FTS" '
        '/v EnableRID44231 /t REG_DWORD /d 0 /f', timeout=4)
    run('reg add "HKLM\\SOFTWARE\\NVIDIA Corporation\\Global\\FTS" '
        '/v EnableRID64640 /t REG_DWORD /d 0 /f', timeout=4)
    run('reg add "HKLM\\SOFTWARE\\NVIDIA Corporation\\Global\\FTS" '
        '/v EnableRID66610 /t REG_DWORD /d 0 /f', timeout=4)
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\Global\\NVTweak" '
        '/v NvCplDisableD3dAA /t REG_DWORD /d 1 /f', timeout=4)
    ok()

    step("Forcing GPU preemption and low-latency pipeline")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers]\r\n"
        '"HwSchMode"=dword:00000002\r\n'
        '"TdrDelay"=dword:0000001e\r\n'
        '"TdrDdiDelay"=dword:0000001e\r\n'
        '"TdrLevel"=dword:00000003\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Scheduler]\r\n"
        '"EnablePreemption"=dword:00000001\r\n'
        '"VsyncIdleTimeout"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile]\r\n"
        '"NetworkThrottlingIndex"=dword:ffffffff\r\n'
        '"SystemResponsiveness"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games]\r\n"
        '"GPU Priority"=dword:00000008\r\n'
        '"Priority"=dword:00000006\r\n'
        '"Scheduling Category"="High"\r\n'
        '"SFIO Priority"="High"\r\n'
        '"Background Only"="False"\r\n'
        '"Clock Rate"=dword:00002710\r\n'
        "\r\n"
    )
    ok()

    step("Disabling GameBar, DVR and overlays")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR]\r\n"
        '"AppCaptureEnabled"=dword:00000000\r\n'
        '"HistoricalCaptureEnabled"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\System\\GameConfigStore]\r\n"
        '"GameDVR_Enabled"=dword:00000000\r\n'
        '"GameDVR_FSEBehaviorMode"=dword:00000002\r\n'
        '"GameDVR_DXGIHonorFSEWindowsCompatible"=dword:00000001\r\n'
        '"GameDVR_HonorUserFSEBehaviorMode"=dword:00000001\r\n'
        '"GameDVR_EFSEFeatureFlags"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR]\r\n"
        '"AllowGameDVR"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\GameBar]\r\n"
        '"AllowAutoGameMode"=dword:00000001\r\n'
        '"AutoGameModeEnabled"=dword:00000001\r\n'
        '"UseNexusForGameBarEnabled"=dword:00000000\r\n'
        "\r\n"
    )
    ok()

    step("Optimizing NTFS and I/O scheduler for game assets")
    run("fsutil behavior set disablelastaccess 1",  timeout=5)
    run("fsutil behavior set disable8dot3 1",       timeout=5)
    run("fsutil behavior set memoryusage 2",        timeout=5)
    run("fsutil behavior set mftzone 2",            timeout=5)
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem" '
        '/v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f', timeout=4)
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem" '
        '/v NtfsMemoryUsage /t REG_DWORD /d 2 /f', timeout=4)
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" '
        '/v LargeSystemCache /t REG_DWORD /d 0 /f', timeout=4)
    ok()

    step("Flushing standby RAM and zeroing working sets")
    if HAS_PSUTIL:
        SKIP = {"system","registry","smss.exe","csrss.exe","wininit.exe","services.exe","lsass.exe"}
        try:
            k32 = ctypes.windll.kernel32
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    n = (proc.info["name"] or "").lower()
                    if n in SKIP:
                        continue
                    h = k32.OpenProcess(0x0400 | 0x0100, False, proc.info["pid"])
                    if h:
                        k32.SetProcessWorkingSetSize(h, ctypes.c_size_t(-1), ctypes.c_size_t(-1))
                        k32.CloseHandle(h)
                except:
                    pass
        except:
            pass
    ps("[System.GC]::Collect(2,[System.GCCollectionMode]::Forced,$true,$true);"
       "[System.GC]::WaitForPendingFinalizers();"
       "[System.GC]::Collect(2,[System.GCCollectionMode]::Forced,$true,$true)", timeout=10)
    ok()

    step("Boosting IRQ priority for GPU and network")
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" '
        '/v IRQ8Priority /t REG_DWORD /d 1 /f', timeout=4)
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" '
        '/v IRQ16Priority /t REG_DWORD /d 1 /f', timeout=4)
    run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" '
        '/v Win32PrioritySeparation /t REG_DWORD /d 38 /f', timeout=4)
    ok()

    step("Disabling power throttling for all processes")
    reg(
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerThrottling]\r\n"
        '"PowerThrottlingOff"=dword:00000001\r\n'
        "\r\n"
    )
    ps('$p = Get-Process | Where-Object {$_.PriorityClass}; '
       'foreach ($x in $p) { try { '
       '$x.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::High '
       '} catch {} }', timeout=12)
    ok()

    step("Applying network low-latency tweaks for gaming")
    run("netsh int tcp set global autotuninglevel=highlyrestricted", timeout=6)
    run("netsh int tcp set global rss=enabled",                      timeout=6)
    run("netsh int tcp set global chimney=disabled",                 timeout=6)
    run('reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Psched" '
        '/v NonBestEffortLimit /t REG_DWORD /d 0 /f', timeout=4)
    run('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile" '
        '/v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f', timeout=4)
    run("ipconfig /flushdns", timeout=5)
    ok()

    step("Elevating running game processes to High priority")
    if HAS_PSUTIL:
        game_procs = {
            "cs2.exe","csgo.exe","valorant.exe","fortnite.exe","r5apex.exe",
            "eldenring.exe","witcher3.exe","cyberpunk2077.exe","rainbowsix.exe",
            "overwatch.exe","gta5.exe","rocketleague.exe","minecraft.exe","javaw.exe",
            "tslgame.exe","bf4.exe","bf2042.exe","destiny2.exe","cod.exe",
            "warzone.exe","escapefromtarkov.exe","halo_infinite.exe",
            "starfield.exe","dota2.exe","leagueclient.exe","league of legends.exe",
            "r5apex.exe","squadgame.exe","arma3.exe","tarkov.exe","readyornot.exe",
        }
        boosted = 0
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pname = (proc.info["name"] or "").lower()
                if pname in game_procs:
                    proc.nice(psutil.HIGH_PRIORITY_CLASS)
                    try:
                        proc.ionice(psutil.IOPRIO_HIGH)
                    except:
                        pass
                    boosted += 1
            except:
                pass
        if boosted:
            print(f"\n    {boosted} game process(es) set to High priority", end="")
    ok()


def gamerun():
    print()
    print("  Preparing gaming mode...")
    print("  Discord and video recorders will stay open.")
    print()
    gsvcs()
    gkill()
    gram()
    gcpu()
    gnet()
    fps()
    print()
    print("  Gaming mode active! Launch your game now.")
    print("  Tip: Run your game as Administrator for best results.")

def main():
    banner()

    if not admin():
        print("  WARNING: Not running as admin.")
        print("  Right-click -> Run as administrator for best results.\n")

    if not HAS_PSUTIL:
        step("Installing psutil")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "psutil", "--quiet"],
                timeout=60,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            ok()
            print("  Restart the script for full RAM features.\n")
        except:
            print("failed. Some features limited.\n")

    specs()

    print("  [1] Hex Tweaker  ")
    print("  [2] Hex Net Booster  ")
    print("  [3] Hex GPU Optimizer  ")
    print("  [4] Hex Display Tuner  ")
    print("  [5] Hex Gaming Mode  ")
    print("  [6] Hex Repair Tool  ")
    print("  [Q] Quit  ")
    print()

    choice = input("  Enter: ").strip().upper()

    if choice == "Q":
        sys.exit(0)
    elif choice == "1":
        tweaker()
    elif choice == "2":
        netrun()
    elif choice == "3":
        gpurun()
    elif choice == "4":
        disprun()
    elif choice == "5":
        gamerun()
    elif choice == "6":
        repairrun()
    else:
        print("  Invalid. Enter 1-6 or Q.")
        return

    print()
    if choice == "5":
        input("  Press Enter to exit...")
        return

    after()

if __name__ == "__main__":
    main()
