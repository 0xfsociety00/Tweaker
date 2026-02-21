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
    r"         Hex-win10 Tweaker v1.0.0",
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
        if isinstance(c, list):
            r = subprocess.run(
                c, shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True, timeout=timeout
            )
        else:
            r = subprocess.run(
                c, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True, timeout=timeout
            )
        return r.returncode == 0, r.stdout.strip()
    except:
        return False, ""


def ps(script, timeout=15):
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
            'powershell -NoProfile -NonInteractive -Command '
            '"(Get-WmiObject Win32_VideoController | Select-Object -First 1).Name"',
            timeout=8
        )
        if ok2 and out2:
            print(f"    GPU     : {out2.strip()}")
    print()


def nvcheck():
    r, out = rout(
        "nvidia-smi --query-gpu=name --format=csv,noheader,nounits",
        timeout=4
    )
    return r and bool(out)


def amdcheck():
    r, out = rout("wmic path win32_VideoController get name", timeout=6)
    return r and ("AMD" in out.upper() or "RADEON" in out.upper())


def pingms(host):
    r, out = rout(f"ping -n 1 -w 500 {host}", timeout=4)
    if r and out:
        for part in out.split():
            p = part.lower()
            if p.startswith("time=") or p.startswith("time<"):
                try:
                    return int(p.replace("time=", "").replace("time<", "").replace("ms", ""))
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
                name = l.split(":", 1)[1].strip()
                if name:
                    adapters.append(name)
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


def bloat():
    step("Killing bloat processes")
    if not HAS_PSUTIL:
        ok()
        return
    targets = {
        "msedge.exe", "microsoftedge.exe", "microsoftedgeupdate.exe",
        "searchindexer.exe", "searchapp.exe", "searchui.exe",
        "onedrive.exe", "onedrivesetup.exe", "onedriveupdater.exe",
        "skypeapp.exe", "skype.exe", "skypebridge.exe",
        "yourphone.exe", "phoneexperiencehost.exe",
        "winstore.app.exe", "winstorerep.exe",
        "gamebar.exe", "gamebarftserver.exe", "gamebarpresencewriter.exe",
        "teams.exe", "ms-teams.exe", "teamsupdatedaemon.exe",
        "cortana.exe", "lockapp.exe",
        "widgetservice.exe", "widgets.exe",
        "xboxapp.exe", "xboxgameoverlay.exe", "xboxidleclientcore.exe",
        "speechruntime.exe", "speechexperiencetranscriber.exe",
        "tabtip.exe", "tabtip32.exe",
        "people.exe", "wallet.exe",
        "windowsmaps.exe", "bingmaps.exe",
        "getstarted.exe", "windowsfeedbackhub.exe",
        "msteamsupdate.exe", "msteams.exe",
        "adobecrashhandler.exe", "adobecrashhandler64.exe",
        "acrord32.exe",
        "jusched.exe",
        "nvinstrument.exe",
        "nvsgssync.exe",
        "nvcplui.exe",
        "nvbackend.exe",
        "nvcvui.exe",
        "eadm.exe",
        "razersynapse.exe", "razercentralservice.exe",
        "igccui.exe",
        "igcctray.exe",
        "logioverlay.exe", "logimgrui.exe",
        "itype.exe", "point32.exe",
        "aisuiteiii.exe",
        "armoryfrontend.exe", "asus_framework.exe",
        "rgbsync.exe",
        "signalrgb.exe",
        "openrgb.exe",
        "iccue.exe",
        "msiafterburner.exe",
        "rtss.exe",
        "hwinfo64.exe",
        "cpuz.exe", "gpuz.exe",
        "speccy.exe",
    }
    snapped = list(psutil.process_iter(["pid", "name"]))
    killed = 0
    for proc in snapped:
        try:
            if proc.info["name"] and proc.info["name"].lower() in targets:
                proc.kill()
                killed += 1
                time.sleep(0.02)
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
        os.path.join(lad, "Microsoft", "Windows", "Explorer"),
        os.path.join(lad, "CrashDumps"),
        os.path.join(lad, "D3DSCache"),
        os.path.join(apd, "Microsoft", "Windows", "Recent"),
        os.path.join(win, "Logs"),
        os.path.join(win, "Minidump"),
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
        os.path.join(lad, "Google", "Chrome", "User Data", "Default", "Cache"),
        os.path.join(lad, "Google", "Chrome", "User Data", "Default", "Code Cache"),
        os.path.join(lad, "Google", "Chrome", "User Data", "Default", "GPUCache"),
        os.path.join(lad, "Google", "Chrome", "User Data", "Default", "Service Worker", "CacheStorage"),
        os.path.join(lad, "Google", "Chrome", "User Data", "ShaderCache"),
        os.path.join(lad, "Microsoft", "Edge", "User Data", "Default", "Cache"),
        os.path.join(lad, "Microsoft", "Edge", "User Data", "Default", "Code Cache"),
        os.path.join(lad, "Microsoft", "Edge", "User Data", "Default", "GPUCache"),
        os.path.join(lad, "Microsoft", "Edge", "User Data", "ShaderCache"),
        os.path.join(lad, "Opera Software", "Opera Stable", "Cache"),
        os.path.join(lad, "Opera Software", "Opera GX Stable", "Cache"),
        os.path.join(lad, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cache"),
        os.path.join(lad, "BraveSoftware", "Brave-Browser", "User Data", "Default", "GPUCache"),
        os.path.join(lad, "Vivaldi", "User Data", "Default", "Cache"),
        os.path.join(lad, "Arc", "User Data", "Default", "Cache"),
        os.path.join(lad, "Tor Browser", "Browser", "TorBrowser", "Data", "Browser", "profile.default", "cache2"),
    ]
    for p in paths:
        if os.path.isdir(p):
            wipe(p)
    ff = os.path.join(lad, "Mozilla", "Firefox", "Profiles")
    if os.path.isdir(ff):
        try:
            for profile in Path(ff).iterdir():
                for sub in ["cache2", "startupCache", "thumbnails", "shader-cache"]:
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
        (sp,       "SystemResponsiveness",   20),
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
        f"  $pf.InitialSize = {pf_init}; "
        f"  $pf.MaximumSize = {pf_max}; "
        "  $pf.Put() | Out-Null "
        "}"
    )
    ps(ps_script, timeout=12)
    if HAS_PSUTIL:
        try:
            k32  = ctypes.windll.kernel32
            SKIP = {"system","registry","smss.exe","csrss.exe","wininit.exe","services.exe","lsass.exe"}
            snapped = list(psutil.process_iter(["pid", "name"]))
            for proc in snapped:
                try:
                    n = (proc.info["name"] or "").lower()
                    if n in SKIP:
                        continue
                    h = k32.OpenProcess(0x0100, False, proc.info["pid"])
                    if h:
                        k32.SetProcessWorkingSetSize(h, ctypes.c_size_t(-1), ctypes.c_size_t(-1))
                        k32.CloseHandle(h)
                        time.sleep(0.005)
                except:
                    pass
        except:
            pass
    ok()


def power():
    step("Setting High Performance power plan")
    HP = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    run(f"powercfg /setactive {HP}", timeout=8)
    run(f"powercfg -duplicatescheme {HP}", timeout=8)
    run(f"powercfg /setactive {HP}", timeout=8)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_USB USBSELECTIVESUSPEND 0",     timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 5",   timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100", timeout=6)
    run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 1",     timeout=6)
    run("powercfg -h off", timeout=6)
    ok()


def gaming():
    step("Applying gaming registry tweaks")
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
        '"GameDVR_FSEBehavior"=dword:00000002\r\n'
        '"GameDVR_EFSEFeatureFlags"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\GameBar]\r\n"
        '"AutoGameModeEnabled"=dword:00000001\r\n'
        '"AllowAutoGameMode"=dword:00000001\r\n'
        '"ShowStartupPanel"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers]\r\n"
        '"HwSchMode"=dword:00000002\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl]\r\n"
        '"Win32PrioritySeparation"=dword:00000026\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile]\r\n"
        '"NetworkThrottlingIndex"=dword:ffffffff\r\n'
        '"SystemResponsiveness"=dword:00000014\r\n'
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
    step("Optimizing GPU driver")
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
        elif any(x in name for x in ["5060","5070","5080","5090"]):
            gen = 50
        run("nvidia-smi --auto-boost-default=0", timeout=6)
        if gen >= 20:
            run("nvidia-smi --persistence-mode=1", timeout=6)
    gd = r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
    for name, val in [("HwSchMode", 2), ("TdrDelay", 10), ("TdrDdiDelay", 10)]:
        run(f'reg add "{gd}" /v {name} /t REG_DWORD /d {val} /f', timeout=5)
    ok()


def visual():
    step("Disabling animations and visual effects")
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
        '"UserPreferencesMask"=hex:90,12,03,80,10,00,00,00\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Control Panel\\Desktop\\WindowMetrics]\r\n"
        '"MinAnimate"="0"\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced]\r\n"
        '"TaskbarAnimations"=dword:00000000\r\n'
        '"ListviewShadow"=dword:00000000\r\n'
        '"ListviewAlphaSelect"=dword:00000000\r\n'
        '"ExtendedUIHoverTime"=dword:00000001\r\n'
        '"TaskbarSmallIcons"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\DWM]\r\n"
        '"EnableAeroPeek"=dword:00000000\r\n'
        '"AlwaysHibernateThumbnails"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize]\r\n"
        '"EnableTransparency"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Dwm]\r\n"
        '"OverlayTestMode"=dword:00000005\r\n'
        '"DisableHWAcceleration"=dword:00000000\r\n'
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
    step("Cleaning startup entries")
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
        '"AdobeARM"=-\r\n'
        '"CCleaner"=-\r\n'
        '"Dropbox"=-\r\n'
        '"GoogleDrive"=-\r\n'
        '"Cortana"=-\r\n'
        '"RazerSynapse"=-\r\n'
        '"iCUE"=-\r\n'
        '"SignalRGB"=-\r\n'
        '"OpenRGB"=-\r\n'
        '"MSIAfterburner"=-\r\n'
        '"RTSS"=-\r\n'
        '"NvBackend"=-\r\n'
        '"SteelSeriesGG"=-\r\n'
        '"ASUS_Framework"=-\r\n'
        '"LogiOptions"=-\r\n'
        '"LogiMgrUI"=-\r\n'
        '"GeForce Experience"=-\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"
        '"OneDrive"=-\r\n'
        '"MicrosoftEdgeUpdate"=-\r\n'
        '"EpicGamesLauncher"=-\r\n'
        '"Teams"=-\r\n'
        '"Cortana"=-\r\n'
        '"NvBackend"=-\r\n'
        "\r\n"
    )
    for t in [
        "OneDrive",
        "MicrosoftEdgeUpdateTaskMachineCore",
        "MicrosoftEdgeUpdateTaskMachineUA",
        "GoogleUpdateTaskMachineCore",
        "GoogleUpdateTaskMachineUA",
        "AdobeGCInvoker-1.0",
        "Adobe Acrobat Update Task",
        "CCleaner Update",
    ]:
        run(f'schtasks /Change /TN "{t}" /Disable', timeout=4)
    ok()


def telem():
    step("Disabling telemetry and tracking")
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
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat]\r\n"
        '"AITEnable"=dword:00000000\r\n'
        '"DisableUAR"=dword:00000001\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows]\r\n"
        '"CEIPEnable"=dword:00000000\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\CompatTelRunner.exe]\r\n"
        '"Debugger"="%%SystemRoot%%\\\\System32\\\\taskkill.exe"\r\n'
        "\r\n"
    )
    for svc in ["DiagTrack", "dmwappushservice", "WerSvc", "PcaSvc",
                "diagnosticshub.standardcollector.service", "DcpSvc"]:
        try:
            subprocess.Popen(["sc", "stop", svc],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
    time.sleep(1)
    for svc in ["DiagTrack", "dmwappushservice", "WerSvc", "PcaSvc",
                "diagnosticshub.standardcollector.service", "DcpSvc"]:
        try:
            subprocess.Popen(["sc", "config", svc, "start=", "disabled"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
    ok()


def storage():
    step("Optimizing storage settings")
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
    dtype = out.strip().upper() if r else ""
    if "SSD" in dtype or "NVM" in dtype:
        run("fsutil behavior set DisableDeleteNotify 0",   timeout=5)
        run("fsutil behavior set disable8dot3 1",          timeout=5)
        run("fsutil behavior set encryptpagingfile 0",     timeout=5)
        run('schtasks /Change /TN "Microsoft\\Windows\\Defrag\\ScheduledDefrag" /Disable', timeout=5)
        svcoff(["SysMain"])
    else:
        run("sc config SysMain start= auto", timeout=5)
        run("sc start SysMain",              timeout=5)
    run("fsutil behavior set memoryusage 2", timeout=5)
    run("fsutil behavior set mftzone 2",     timeout=5)
    ok()


def svcs():
    step("Disabling unnecessary background services")
    svcoff([
        "Fax", "WMPNetworkSvc", "RemoteRegistry", "MapsBroker", "PhoneSvc",
        "XblGameSave", "XblAuthManager", "lfsvc", "wisvc", "TabletInputService",
        "WbioSrvc", "icssvc", "RetailDemo", "DusmSvc", "WalletService",
        "MessagingService", "PimIndexMaintenanceSvc", "OneSyncSvc",
        "UnistoreSvc", "UserDataSvc", "diagsvc", "wercplsupport",
        "DiagTrack", "dmwappushservice",
        "TrkWks",
        "BDESVC",
        "lltdsvc",
        "SharedAccess",
        "lmhosts",
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
        '"NtfsDisable8dot3NameCreation"=dword:00000001\r\n'
        "\r\n"
        "[HKEY_CURRENT_USER\\Control Panel\\Desktop]\r\n"
        '"AutoEndTasks"="1"\r\n'
        '"HungAppTimeout"="2000"\r\n'
        '"WaitToKillAppTimeout"="5000"\r\n'
        "\r\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control]\r\n"
        '"WaitToKillServiceTimeout"="5000"\r\n'
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
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel]\r\n"
        '"GlobalTimerResolutionRequests"=dword:00000001\r\n'
        "\r\n"
    )
    ok()


def net_quick():
    step("Quick network boost")
    run("ipconfig /flushdns", timeout=5)
    run("netsh int tcp set global autotuninglevel=normal",  timeout=6)
    run("netsh int tcp set global chimney=disabled",        timeout=6)
    run("netsh int tcp set global rss=enabled",             timeout=6)
    run("netsh int tcp set global netdma=enabled",          timeout=6)
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
    step("Boosting detected game processes")
    if not HAS_PSUTIL:
        ok()
        return
    targets = {
        "cs2.exe", "csgo.exe", "valorant.exe", "fortnite.exe", "r5apex.exe",
        "overwatch.exe", "overwatch2.exe", "rainbowsix.exe", "siege.exe",
        "cod.exe", "warzone.exe", "modernwarfare.exe",
        "rocketleague.exe", "dota2.exe", "leagueclient.exe", "leagueoflegends.exe",
        "tslgame.exe",
        "eldenring.exe", "witcher3.exe", "cyberpunk2077.exe",
        "gta5.exe", "gtav.exe",
        "bf4.exe", "bf1.exe", "bf5.exe", "bf2042.exe",
        "destiny2.exe", "halo_infinite.exe", "starfield.exe",
        "escapefromtarkov.exe",
        "sekiro.exe", "darksoulsiii.exe", "armoredcorevi.exe",
        "re2.exe", "re3.exe", "re4.exe", "re8.exe", "re_chunk_000.exe",
        "mhw.exe", "mhrise.exe",
        "ghostrunner.exe", "deathloop.exe",
        "horizonzerodawn.exe",
        "thewitcher2.exe",
        "xcom2.exe",
        "totalwarhammer3.exe",
        "fsd-win64-shipping.exe",
        "palworld.exe", "pal-win64-shipping.exe",
        "helldivers2.exe", "hd2-win64-shipping.exe",
        "marvelrivals.exe", "marvel-win64-shipping.exe",
        "minecraft.exe", "javaw.exe", "minecraftlauncher.exe",
        "assettocorsa.exe", "acs.exe",
        "eurotrucksimulator2.exe", "americantrucksimulator.exe",
        "f12023.exe", "f12024.exe", "f12025.exe",
        "forzamotorsport.exe",
        "rfactor2.exe", "iracing.exe",
        "ffxiv.exe", "ffxiv_dx11.exe",
        "pathofexile.exe", "pathofexile2.exe",
        "diablo4.exe", "diablo3.exe",
        "worldofwarcraft.exe", "wow.exe",
        "runescape.exe", "osclient.exe",
        "starcraft2.exe", "sc2.exe",
        "aoe4.exe",
        "hyperscape.exe",
        "naraka.exe", "naraka-win64-shipping.exe",
        "terraria.exe",
        "valheim.exe",
    }
    snapped = list(psutil.process_iter(["pid", "name"]))
    n = 0
    for proc in snapped:
        try:
            pname = (proc.info["name"] or "").lower()
            if pname in targets:
                proc.nice(psutil.HIGH_PRIORITY_CLASS)
                try:
                    proc.ionice(psutil.IOPRIO_HIGH)
                except:
                    pass
                n += 1
        except:
            pass
    ok()
    if n:
        print(f"    {n} game process(es) boosted to HIGH priority")


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
    net_quick()
    procs()
    print()
    print("  All done! Restart your PC for full effect.")
    if nvcheck():
        print("  Tip: NVIDIA Control Panel -> Prefer Maximum Performance.")


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
                        try:
                            current = int(parts[0])
                        except:
                            pass
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


def adapters():
    step("Tuning network adapter registry settings")
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


def wifi():
    step("Optimizing WiFi adapter")
    wlan = wifiadp()
    if not wlan:
        ok()
        print("    No WiFi adapters found, skipping")
        return
    for adapter in wlan:
        safe = adapter.strip().replace("'", "").replace('"', "")
        if not safe:
            continue
        for kw, val in [
            ("RoamAggressiveness",   "1"),
            ("*TransmitBuffers",     "1024"),
            ("*ReceiveBuffers",      "1024"),
            ("*InterruptModeration", "0"),
            ("*PriorityVLANTag",     "0"),
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
    r, profiles_out = rout("netsh wlan show profiles", timeout=6)
    if r and profiles_out:
        for line in profiles_out.splitlines():
            if ":" in line and ("All User Profile" in line or "User Profile" in line):
                profile_name = line.split(":", 1)[1].strip()
                if profile_name:
                    run(
                        f'netsh wlan set profileparameter name="{profile_name}" connectionmode=auto',
                        timeout=5
                    )
    ok()


def dns():
    step("Finding fastest DNS server")
    DNS = [
        ("Cloudflare", "1.1.1.1",        "1.0.0.1"),
        ("Google",     "8.8.8.8",         "8.8.4.4"),
        ("Quad9",      "9.9.9.9",         "149.112.112.112"),
        ("OpenDNS",    "208.67.222.222",  "208.67.220.220"),
        ("AdGuard",    "94.140.14.14",    "94.140.15.15"),
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
    step("Removing bandwidth throttle limits")
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
    run("netsh int ip set global taskoffload=enabled",     timeout=6)
    run("netsh int ip set global neighborcachelimit=4096", timeout=6)
    run("netsh int ip set global routecachelimit=4096",    timeout=6)
    ok()


def netreset():
    step("Resetting network stack")
    run("netsh winsock reset",  timeout=10)
    run("netsh int ip reset",   timeout=10)
    run("netsh int tcp reset",  timeout=8)
    run("netsh int ipv6 reset", timeout=8)
    run("ipconfig /release",    timeout=12)
    run("ipconfig /renew",      timeout=18)
    run("ipconfig /flushdns",   timeout=5)
    ok()


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


def main():
    banner()

    if not admin():
        print("  WARNING: Not running as administrator.")
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
            print("failed. Some features will be limited.\n")

    specs()

    print("  [1] Hex Tweaker")
    print("  [2] Hex Net Booster")
    print("  [Q] Quit")
    print()

    choice = input("  Enter: ").strip().upper()

    if choice == "Q":
        sys.exit(0)
    elif choice == "1":
        tweaker()
    elif choice == "2":
        netrun()
    else:
        print("  Invalid. Enter 1, 2, or Q.")
        input("  Press Enter to exit...")
        return

    print()
    r = input("  Restart now? (y/N): ").strip().lower()
    if r == "y":
        for i in range(5, 0, -1):
            print(f"  Restarting in {i}...", end="\r")
            time.sleep(1)
        run("shutdown /r /t 0")
    else:
        input("  Press Enter to exit...")


if __name__ == "__main__":
    main()
