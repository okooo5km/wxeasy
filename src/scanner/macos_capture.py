"""LLDB PBKDF2 capture adapted from pandorafuture/wx-cli (MIT).

See doc/pandorafuture-MIT.txt. Integration: okooo5km(十里).
Only invoked by explicit init --live / --relaunch on macOS arm64.
"""
import json
import os
import subprocess
import time

import lldb

_seen = set()


def pbkdf_callback(frame, bp_loc, internal_dict):
    def reg(name):
        return frame.FindRegister(name).GetValueAsUnsigned()

    # CommonCrypto ABI: PBKDF2, 32-byte password, 16-byte salt, SHA512, 256K.
    if (reg("x0"), reg("x2"), reg("x4"), reg("x5"), reg("x6")) != (
        2, 32, 16, 5, 256000
    ):
        return False
    process = frame.GetThread().GetProcess()
    error = lldb.SBError()
    password = process.ReadMemory(reg("x1"), 32, error)
    if not error.Success() or len(password) != 32:
        return False
    salt = process.ReadMemory(reg("x3"), 16, error)
    if not error.Success() or len(salt) != 16:
        return False
    pair = (password.hex(), salt.hex())
    if pair not in _seen and len(_seen) < 32:
        _seen.add(pair)
        # Private pipe to the parent, never a diagnostic log or disk file.
        print("WXEASY_KEY " + json.dumps({"password": pair[0], "salt": pair[1]}), flush=True)
    return False


def capture(debugger, command, result, internal_dict):
    _seen.clear()
    process = None
    target = None
    try:
        debugger.SetAsync(True)
        mode = os.environ["WXEASY_CAPTURE_MODE"]
        target = debugger.CreateTarget("/Applications/WeChat.app/Contents/MacOS/WeChat")
        if not target.IsValid() or not target.GetTriple().startswith("arm64"):
            raise RuntimeError("LLDB capture requires the arm64 WeChat executable in /Applications")
        bp = target.BreakpointCreateByName("CCKeyDerivationPBKDF")
        bp.SetScriptCallbackFunction(__name__ + ".pbkdf_callback")
        error = lldb.SBError()
        if mode == "relaunch":
            subprocess.run(["killall", "WeChat"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)
            launch = lldb.SBLaunchInfo([])
            launch.SetLaunchFlags(lldb.eLaunchFlagDebug | lldb.eLaunchFlagStopAtEntry)
            # The detached application must not keep the private capture pipe open.
            launch.AddOpenFileAction(0, "/dev/null", True, False)
            launch.AddOpenFileAction(1, "/dev/null", False, True)
            launch.AddOpenFileAction(2, "/dev/null", False, True)
            process = target.Launch(launch, error)
        else:
            pids = subprocess.check_output(["pgrep", "-x", "WeChat"], text=True).split()
            if len(pids) != 1:
                raise RuntimeError("Expected exactly one WeChat process")
            process = target.AttachToProcessWithID(debugger.GetListener(), int(pids[0]), error)
        if error.Fail():
            raise RuntimeError("Cannot debug WeChat; check SIP and Developer Tools permissions")
        # LLDB's initial attach/launch stop may be SIGSTOP; resume it once.
        initial_stop = True
        if process.GetState() == lldb.eStateStopped:
            process.Continue()
            initial_stop = False
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            state = process.GetState()
            if state in (lldb.eStateExited, lldb.eStateDetached, lldb.eStateInvalid):
                break
            if state == lldb.eStateStopped:
                if initial_stop:
                    initial_stop = False
                    process.Continue()
                    continue
                # Do not swallow a crash, signal, or unrelated debugger stop.
                reasons = [t.GetStopReason() for t in process]
                allowed = (lldb.eStopReasonNone, lldb.eStopReasonInvalid,
                           lldb.eStopReasonBreakpoint, lldb.eStopReasonExec)
                if any(r not in allowed for r in reasons):
                    break
                process.Continue()
            time.sleep(0.05)
    except Exception:
        print("WXEASY_ERROR LLDB capture failed; check WeChat, SIP and Developer Tools permissions", flush=True)
    finally:
        if process and process.IsValid() and process.GetState() not in (
            lldb.eStateExited, lldb.eStateDetached, lldb.eStateInvalid
        ):
            debugger.SetAsync(False)
            process.Stop()
            if target:
                target.DeleteAllBreakpoints()
            error = process.Detach()
            if error.Fail():
                print("WXEASY_ERROR Could not detach LLDB; inspect WeChat before retrying", flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("command script add -f " + __name__ + ".capture wxeasy_capture")
