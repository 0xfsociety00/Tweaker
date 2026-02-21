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
    r"         Hex-win10 Tweaker v67",
    r"     made with <3 by @hex1 on TikTok",
]

def print_banner():
    os.system("cls" if os.name == "nt" else "clear")
    for line in BANNER_LINES:
        for ch in line:
            sys.stdout.write(ch)
            sys.stdout.flush()
            time.sleep(0.011)
        sys.stdout.write("\n")
        sys.stdout.flush()
    print()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def cmd(c, timeout=12):
    try:
        subprocess.run(
            c, shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout
        )
    except:
        pass

def cmd_out(c, timeout=10):
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

def ps_run(script, timeout=12):
    """Run a PowerShell script string safely — no quote escaping issues."""
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout
        )
    except:
        pass

def apply_reg(content):
    """Write a .reg file and silently import it. Fully hardened against temp-file failures."""
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".reg")
        # write UTF-16 LE with BOM — required by regedit
        with os.fdopen(fd, "wb") as f:
            f.write(b"\xff\xfe")  # UTF-16 LE BOM
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

def svc_kill(names):
    """Stop and disable services. Fire all stops simultaneously, wait, then disable."""
    # launch all stops at once
    for n in names:
        try:
            subprocess.Popen(
                ["sc", "stop", n],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except:
            pass
    # give them time to stop — no SCM deadlock risk at 2s
    time.sleep(2)
    # disable all — also fire simultaneously
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

def done():
    print("done!")

def show_specs():
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
    ok, out = cmd_out(
        "nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader,nounits",
        timeout=5
    )
    if ok and out:
        parts = [x.strip() for x in out.split(",")]
        if len(parts) >= 3:
            print(f"    GPU     : {parts[0]}  |  VRAM {parts[2]}/{parts[1]} MB")
    else:
        ok2, out2 = cmd_out(
            'powershell -NoProfile -NonInteractive -Command "(Get-WmiObject Win32_VideoController | Select-Object -First 1).Name"',
            timeout=8
        )
        if ok2 and out2:
            print(f"    GPU     : {out2.strip()}")
    print()

def _ping_ms(host):
    ok, out = cmd_out(f"ping -n 1 -w 500 {host}", timeout=4)
    if ok and out:
        for part in out.split():
            p = part.lower()
            if p.startswith("time=") or p.startswith("time<"):
                try:
                    return int(p.replace("time=","").replace("time<","").replace("ms",""))
                except:
                    pass
    return None

def _get_wifi_adapters():
    ok, out = cmd_out("netsh wlan show interfaces", timeout=6)
    adapters = []
    if ok and out:
        for line in out.splitlines():
            l = line.strip()
            if l.lower().startswith("name") and ":" in l:
                adapters.append(l.split(":", 1)[1].strip())
    return adapters

def _get_all_adapters():
    ok, out = cmd_out("netsh interface show interface", timeout=6)
    ifaces = []
    if ok and out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] in ("Connected", "Enabled"):
                ifaces.append(" ".join(parts[3:]))
    return ifaces

def _has_nvidia():
    ok, out = cmd_out(
        "nvidia-smi --query-gpu=name --format=csv,noheader,nounits",
        timeout=4
    )
    return ok and bool(out)


# ── TWEAKER ───────────────────────────────────────────────────────────────────

def kill_bloat():
    step("Killing bloat processes")
    if not HAS_PSUTIL:
        done()
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
    done()
    if killed:
        print(f"    {killed} processes killed")

def clean_temp():
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
    cmd("rd /s /q %SystemDrive%\\$Recycle.Bin", timeout=8)
    done()

def clean_browsers():
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
    done()

def ram_optimize():
    step("Optimizing RAM")

    total_gb = gb(psutil.virtual_memory().total) if HAS_PSUTIL else 8

    mm       = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    pf_param = mm + r"\PrefetchParameters"
    sp       = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"

    # individual reg calls — simple, no f-string issues, no .reg file needed
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
        cmd(f'reg add "{key}" /v "{name}" /t REG_DWORD /d {val} /f', timeout=5)

    # pagefile via PowerShell — FIXED: use list args to avoid all quoting issues
    if total_gb <= 8:
        pf_init, pf_max = 8192, 16384
    elif total_gb <= 16:
        pf_init, pf_max = 4096, 8192
    elif total_gb <= 32:
        pf_init, pf_max = 2048, 4096
    else:
        pf_init, pf_max = 1024, 2048

    # Build the PS script as a plain string — NO f-string curly braces around PS variables
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
    ps_run(ps_script, timeout=12)

    # trim working sets — use PROCESS_SET_QUOTA (0x0100) instead of PROCESS_ALL_ACCESS
    # avoids hanging on protected processes that reject the full access mask
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
                    # 0x0100 = PROCESS_SET_QUOTA — minimal rights, never hangs
                    h = k32.OpenProcess(0x0100, False, proc.info["pid"])
                    if h:
                        k32.SetProcessWorkingSetSize(h, ctypes.c_size_t(-1), ctypes.c_size_t(-1))
                        k32.CloseHandle(h)
                except:
                    pass
        except:
            pass

    done()

def power_boost():
    step("Boosting CPU and power plan")
    HP = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    cmd(f"powercfg /setactive {HP}", timeout=8)
    cmd(f"powercfg -duplicatescheme {HP}", timeout=8)
    cmd(f"powercfg /setactive {HP}", timeout=8)
    cmd("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_USB USBSELECTIVESUSPEND 0",         timeout=6)
    cmd("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100",     timeout=6)
    cmd("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100",     timeout=6)
    cmd("powercfg -h off", timeout=6)
    done()

def gaming_tweaks():
    step("Applying gaming tweaks")
    apply_reg(
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
    done()

def gpu_optimize():
    step("Optimizing GPU")
    ok, out = cmd_out(
        "nvidia-smi --query-gpu=name --format=csv,noheader,nounits",
        timeout=5
    )
    if ok and out:
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
        cmd("nvidia-smi --auto-boost-default=0", timeout=6)
        if gen >= 20:
            cmd("nvidia-smi --persistence-mode=1", timeout=6)
    gd = r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
    for name, val in [("HwSchMode", 2), ("TdrDelay", 10), ("TdrDdiDelay", 10)]:
        cmd(f'reg add "{gd}" /v {name} /t REG_DWORD /d {val} /f', timeout=5)
    done()

def visual_optimize():
    step("Removing animations and visual effects")
    apply_reg(
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
    # apply animations off live — proper ctypes struct, no crash
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
    done()

def startup_clean():
    step("Cleaning startup programs")
    apply_reg(
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
        cmd(f'schtasks /Change /TN "{t}" /Disable', timeout=4)
    done()

def telemetry_off():
    step("Disabling telemetry")
    apply_reg(
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
    svc_kill(["DiagTrack", "dmwappushservice", "WerSvc", "PcaSvc"])
    done()

def storage_optimize():
    step("Optimizing storage")
    # detect drive type via PowerShell — no broken quote nesting
    ps_detect = (
        "try { "
        "$disk = (Get-Partition -DriveLetter C -ErrorAction Stop).DiskNumber; "
        "(Get-PhysicalDisk | Where-Object DeviceId -eq $disk).MediaType "
        "} catch { 'Unknown' }"
    )
    ok, out = cmd_out(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_detect],
        timeout=10
    )
    dtype = out.strip().upper() if ok else ""
    if "SSD" in dtype or "NVM" in dtype:
        cmd("fsutil behavior set DisableDeleteNotify 0",                                      timeout=5)
        cmd("fsutil behavior set disable8dot3 1",                                             timeout=5)
        cmd("fsutil behavior set encryptpagingfile 0",                                        timeout=5)
        cmd('schtasks /Change /TN "Microsoft\\Windows\\Defrag\\ScheduledDefrag" /Disable',   timeout=5)
        svc_kill(["SysMain"])
    else:
        cmd("sc config SysMain start= auto", timeout=5)
        cmd("sc start SysMain",              timeout=5)
    done()

def services_clean():
    step("Disabling unnecessary services")
    svc_kill([
        "Fax", "WMPNetworkSvc", "RemoteRegistry", "MapsBroker", "PhoneSvc",
        "XblGameSave", "XblAuthManager", "lfsvc", "wisvc", "TabletInputService",
        "WbioSrvc", "icssvc", "RetailDemo", "DusmSvc", "WalletService",
        "MessagingService", "PimIndexMaintenanceSvc", "OneSyncSvc",
        "UnistoreSvc", "UserDataSvc", "diagsvc", "wercplsupport",
    ])
    done()

def beast_mode():
    step("Applying beast mode tweaks")
    apply_reg(
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
    done()

def network_boost():
    step("Boosting network")
    cmd("ipconfig /flushdns",                                   timeout=5)
    cmd("netsh int tcp set global autotuninglevel=normal",      timeout=6)
    cmd("netsh int tcp set global chimney=disabled",            timeout=6)
    cmd("netsh int tcp set global rss=enabled",                 timeout=6)
    cmd("netsh int tcp set global netdma=enabled",              timeout=6)
    ok, out = cmd_out(
        r'reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"',
        timeout=6
    )
    if ok and out:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("HKEY"):
                cmd(f'reg add "{line}" /v TcpAckFrequency /t REG_DWORD /d 1 /f', timeout=4)
                cmd(f'reg add "{line}" /v TCPNoDelay      /t REG_DWORD /d 1 /f', timeout=4)
                cmd(f'reg add "{line}" /v TcpDelAckTicks  /t REG_DWORD /d 0 /f', timeout=4)
    done()

def game_process_boost():
    step("Boosting game processes")
    if not HAS_PSUTIL:
        done()
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
    done()
    if n:
        print(f"    {n} game process(es) boosted")


# ── NET BOOSTER ───────────────────────────────────────────────────────────────

def net_flush_cache():
    step("Flushing network caches")
    cmd("ipconfig /flushdns",    timeout=5)
    cmd("arp -d *",              timeout=5)
    cmd("nbtstat -R",            timeout=6)
    cmd("nbtstat -RR",           timeout=6)
    cmd("ipconfig /registerdns", timeout=6)
    ps_run("Clear-DnsClientCache -ErrorAction SilentlyContinue", timeout=8)
    done()

def net_tcp_optimize():
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
        cmd(c, timeout=6)
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
        cmd(f'reg add "{tcp}" /v "{name}" /t REG_DWORD /d {val} /f', timeout=4)
    done()

def net_adapter_tune():
    step("Tuning network adapters")
    ok, out = cmd_out(
        r'reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"',
        timeout=6
    )
    if ok and out:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("HKEY"):
                cmd(f'reg add "{line}" /v TcpAckFrequency /t REG_DWORD /d 1 /f', timeout=4)
                cmd(f'reg add "{line}" /v TCPNoDelay      /t REG_DWORD /d 1 /f', timeout=4)
                cmd(f'reg add "{line}" /v TcpDelAckTicks  /t REG_DWORD /d 0 /f', timeout=4)
                cmd(f'reg add "{line}" /v TcpInitialRTT   /t REG_DWORD /d 3 /f', timeout=4)
    done()

def net_wifi_optimize():
    step("Optimizing WiFi")
    adapters = _get_wifi_adapters()
    for adapter in adapters:
        safe = adapter.replace("'","").replace('"',"")
        for kw, val in [
            ("RoamAggressiveness",   "1"),
            ("*TransmitBuffers",     "1024"),
            ("*ReceiveBuffers",      "1024"),
            ("*InterruptModeration", "0"),
        ]:
            ps_run(
                f"Set-NetAdapterAdvancedProperty -Name '{safe}' "
                f"-RegistryKeyword '{kw}' -RegistryValue {val} -ErrorAction SilentlyContinue",
                timeout=8
            )
        ps_run(
            f"Disable-NetAdapterPowerManagement -Name '{safe}' -ErrorAction SilentlyContinue",
            timeout=8
        )
    cmd(
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" '
        r'/v fMinimizeConnections /t REG_DWORD /d 0 /f',
        timeout=4
    )
    cmd("netsh wlan set profileparameter mode=auto", timeout=5)
    done()

def net_dns_boost():
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
        ms = _ping_ms(pri)
        if ms is not None and ms < best_ms:
            best_ms, best_name, best_pri, best_sec = ms, name, pri, sec
    for iface in _get_all_adapters():
        cmd(f'netsh interface ip set dns name="{iface}" static {best_pri} primary', timeout=6)
        cmd(f'netsh interface ip add dns name="{iface}" {best_sec} index=2',        timeout=6)
    cmd("ipconfig /flushdns", timeout=5)
    done()
    print(f"    Best DNS: {best_name} ({best_pri}) at {best_ms}ms")

def net_qos_boost():
    step("Removing bandwidth limits")
    cmd(
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" '
        r'/v NonBestEffortLimit /t REG_DWORD /d 0 /f',
        timeout=4
    )
    cmd(
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" '
        r'/v "Do not use NLA" /t REG_SZ /d "1" /f',
        timeout=4
    )
    cmd(
        r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" '
        r'/v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f',
        timeout=4
    )
    cmd("netsh int ip set global taskoffload=enabled",      timeout=6)
    cmd("netsh int ip set global neighborcachelimit=4096",  timeout=6)
    cmd("netsh int ip set global routecachelimit=4096",     timeout=6)
    done()

def net_winsock_reset():
    step("Resetting network stack")
    cmd("netsh winsock reset", timeout=10)
    cmd("netsh int ip reset",  timeout=10)
    cmd("netsh int tcp reset", timeout=8)
    cmd("netsh int ipv6 reset",timeout=8)
    cmd("ipconfig /release",   timeout=12)
    cmd("ipconfig /renew",     timeout=18)
    cmd("ipconfig /flushdns",  timeout=5)
    done()


# ── RUNNERS ───────────────────────────────────────────────────────────────────

def run_tweaker():
    print()
    kill_bloat()
    clean_temp()
    clean_browsers()
    ram_optimize()
    power_boost()
    gaming_tweaks()
    gpu_optimize()
    visual_optimize()
    startup_clean()
    telemetry_off()
    storage_optimize()
    services_clean()
    beast_mode()
    network_boost()
    game_process_boost()
    print()
    print("  All done! Restart your PC for full effect.")
    if _has_nvidia():
        print("  Set NVIDIA Control Panel -> Prefer Maximum Performance.")

def run_net_booster():
    print()
    net_flush_cache()
    net_tcp_optimize()
    net_adapter_tune()
    net_wifi_optimize()
    net_dns_boost()
    net_qos_boost()
    net_winsock_reset()
    print()
    print("  Net boost complete! Restart your PC for full effect.")


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    print_banner()

    if not is_admin():
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
            done()
            print("  Restart the script for full RAM features.\n")
        except:
            print("failed. Some features limited.\n")

    show_specs()

    print("  [1] Hex Tweaker")
    print("  [2] Hex Net Booster")
    print("  [Q] Quit")
    print()

    choice = input("  Enter: ").strip().upper()

    if choice == "Q":
        sys.exit(0)
    elif choice == "1":
        run_tweaker()
    elif choice == "2":
        run_net_booster()
    else:
        print("  Invalid. Enter 1, 2, or Q.")
        return

    print()
    r = input("  Restart now? (y/N): ").strip().lower()
    if r == "y":
        for i in range(5, 0, -1):
            print(f"  Restarting in {i}...", end="\r")
            time.sleep(1)
        cmd("shutdown /r /t 0")
    else:
        input("  Press Enter to exit...")

if __name__ == "__main__":
    main()
