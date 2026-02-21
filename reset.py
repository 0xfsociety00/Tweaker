import os
import sys
import subprocess
import ctypes
import time

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

def ps(script, timeout=15):
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-WindowStyle", "Hidden", "-Command", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout
        )
    except:
        pass

def say(msg):
    print(f"  {msg}...", end=" ", flush=True)

def ok():
    print("done!")

def chk(label, val):
    print(f"  {label:<48} {val}")

print(" this fuckass tweak reset everything for the cpu ")

if not admin():
    print("  ERROR: Run as administrator.")
    input("  Press Enter to exit.")
    sys.exit(1)


r, out = rout(
    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" '
    '/v DisablePagingExecutive', timeout=5
)
if r and out:
    val = out.split()[-1] if out.split() else "?"
    chk("DisablePagingExecutive", f"{val}  (want 0x0)")

r, out = rout(
    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" '
    '/v PoolUsageMaximum', timeout=5
)
if r and out:
    val = out.split()[-1] if out.split() else "?"
    chk("PoolUsageMaximum", f"{val}  (want 0x50 = 80)")

r, out = rout(
    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" '
    '/v Win32PrioritySeparation', timeout=5
)
if r and out:
    val = out.split()[-1] if out.split() else "?"
    chk("Win32PrioritySeparation", f"{val}  (want 0x2 default)")

r, out = rout('powercfg /getactivescheme', timeout=6)
if r and out:
    chk("Active power scheme", out.strip()[:55])

r, out = rout(
    'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile" '
    '/v SystemResponsiveness', timeout=5
)
if r and out:
    val = out.split()[-1] if out.split() else "?"
    chk("SystemResponsiveness", f"{val}  (want 0x14 = 20)")

r, out = rout(
    'reg query "HKCU\\Control Panel\\Desktop" /v AutoEndTasks', timeout=5
)
if r and out:
    val = out.split()[-1] if out.split() else "?"
    chk("AutoEndTasks", f"{val}  (want 0)")

print()


say("Switching to balanced power plan")
run("powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e", timeout=8)
ok()

say("PROCTHROTTLEMIN = 5 (allows idle)")
run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 5", timeout=6)
run("powercfg /SETACVALUEINDEX SCHEME_BALANCED SUB_PROCESSOR PROCTHROTTLEMIN 5", timeout=6)
run('powercfg /SETACVALUEINDEX "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" SUB_PROCESSOR PROCTHROTTLEMIN 5', timeout=6)
ok()

say("PROCTHROTTLEMAX = 100")
run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100", timeout=6)
run("powercfg /SETACVALUEINDEX SCHEME_BALANCED SUB_PROCESSOR PROCTHROTTLEMAX 100", timeout=6)
ok()

say("PERFBOOSTMODE = 1 (normal)")
run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 1", timeout=6)
run("powercfg /SETACVALUEINDEX SCHEME_BALANCED SUB_PROCESSOR PERFBOOSTMODE 1", timeout=6)
ok()

say("Re-enabling core parking (ValueMax = 100)")
run(
    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\'
    '54533251-82be-4824-96c1-47b60b740d00\\0cc5b647-c1df-4637-891a-dec35c318583" '
    '/v ValueMax /t REG_DWORD /d 100 /f', timeout=5
)
ok()

print()


mm = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
pf = mm + r"\PrefetchParameters"

say("DisablePagingExecutive = 0")
run(f'reg add "{mm}" /v DisablePagingExecutive /t REG_DWORD /d 0 /f', timeout=5)
ok()

say("LargeSystemCache = 0")
run(f'reg add "{mm}" /v LargeSystemCache /t REG_DWORD /d 0 /f', timeout=5)
ok()

say("IoPageLockLimit = 0 (auto)")
run(f'reg add "{mm}" /v IoPageLockLimit /t REG_DWORD /d 0 /f', timeout=5)
ok()

say("SecondLevelDataCache = 0 (auto)")
run(f'reg add "{mm}" /v SecondLevelDataCache /t REG_DWORD /d 0 /f', timeout=5)
ok()

say("PoolUsageMaximum = 80")
run(f'reg add "{mm}" /v PoolUsageMaximum /t REG_DWORD /d 80 /f', timeout=5)
ok()

say("PagedPoolSize = 0 (auto)")
run(f'reg add "{mm}" /v PagedPoolSize /t REG_DWORD /d 0 /f', timeout=5)
ok()

say("EnablePrefetcher = 3")
run(f'reg add "{pf}" /v EnablePrefetcher /t REG_DWORD /d 3 /f', timeout=5)
ok()

say("EnableSuperfetch = 3")
run(f'reg add "{pf}" /v EnableSuperfetch /t REG_DWORD /d 3 /f', timeout=5)
ok()

print()


sp = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"

say("SystemResponsiveness = 20")
run(f'reg add "{sp}" /v SystemResponsiveness /t REG_DWORD /d 20 /f', timeout=5)
ok()

say("NetworkThrottlingIndex = 10 (default)")
run(f'reg add "{sp}" /v NetworkThrottlingIndex /t REG_DWORD /d 10 /f', timeout=5)
ok()

say("Win32PrioritySeparation = 2 (Windows default)")
run(
    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" '
    '/v Win32PrioritySeparation /t REG_DWORD /d 2 /f', timeout=5
)
ok()

print()



say("AutoEndTasks = 0")
run('reg add "HKCU\\Control Panel\\Desktop" /v AutoEndTasks /t REG_SZ /d 0 /f', timeout=5)
ok()

say("HungAppTimeout = 5000ms")
run('reg add "HKCU\\Control Panel\\Desktop" /v HungAppTimeout /t REG_SZ /d 5000 /f', timeout=5)
ok()

say("WaitToKillAppTimeout = 20000ms (default)")
run('reg add "HKCU\\Control Panel\\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 20000 /f', timeout=5)
ok()

say("WaitToKillServiceTimeout = 20000ms")
run(
    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control" '
    '/v WaitToKillServiceTimeout /t REG_SZ /d 20000 /f', timeout=5
)
ok()

print()




say("Re-enabling SysMain / Superfetch")
run("sc config SysMain start= auto", timeout=6)
run("sc start SysMain", timeout=8)
ok()

say("Re-enabling Windows Search")
run("sc config WSearch start= delayed-auto", timeout=6)
run("sc start WSearch", timeout=8)
ok()

print()



say("Final power plan activation")
run("powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e", timeout=8)
run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 5", timeout=6)
run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100", timeout=6)
run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 1", timeout=6)
ok()

print()
r, out = rout(
    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" '
    '/v DisablePagingExecutive', timeout=5
)
val = out.split()[-1] if (r and out.split()) else "ERR"
ok_str = "OK" if val == "0x0" else "!! CHECK"
chk("DisablePagingExecutive", f"{val}  {ok_str}")

r, out = rout(
    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" '
    '/v Win32PrioritySeparation', timeout=5
)
val = out.split()[-1] if (r and out.split()) else "ERR"
ok_str = "OK" if val == "0x2" else "!! CHECK"
chk("Win32PrioritySeparation", f"{val}  {ok_str}")

r, out = rout(
    'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile" '
    '/v SystemResponsiveness', timeout=5
)
val = out.split()[-1] if (r and out.split()) else "ERR"
ok_str = "OK" if val == "0x14" else "!! CHECK"
chk("SystemResponsiveness", f"{val}  {ok_str}")

r, out = rout('powercfg /getactivescheme', timeout=6)
if r and out:
    ok_str = "OK (Balanced)" if "381b4222" in out.lower() else "!! still on HP plan"
    chk("Power scheme", ok_str)

print()
print("  Reset complete.")
print()
print(" restart da pc gng")
print(' check ur cpu usage after restart gng ' )

input("  Press Enter to exit.")
