"""Exercise capture filtering and debugger cleanup without accessing WeChat."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


lldb = types.ModuleType("lldb")
for i, name in enumerate(("eStateExited", "eStateDetached", "eStateInvalid", "eStateStopped",
                          "eStateRunning", "eStopReasonNone", "eStopReasonInvalid",
                          "eStopReasonBreakpoint", "eStopReasonExec", "eStopReasonSignal")):
    setattr(lldb, name, i)
lldb.eLaunchFlagDebug = 1
lldb.eLaunchFlagStopAtEntry = 2
lldb.SBError = lambda: types.SimpleNamespace(Success=lambda: True, Fail=lambda: False)
lldb.SBLaunchInfo = MagicMock()
spec = importlib.util.spec_from_file_location(
    "capture_under_test", Path(__file__).resolve().parents[1] / "src/scanner/macos_capture.py")
capture = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"lldb": lldb}):
    spec.loader.exec_module(capture)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        capture._seen.clear()

    def frame(self, **overrides):
        regs = dict(x0=2, x1=100, x2=32, x3=200, x4=16, x5=5, x6=256000)
        regs.update(overrides)
        frame = MagicMock()
        frame.FindRegister.side_effect = lambda n: types.SimpleNamespace(GetValueAsUnsigned=lambda: regs[n])
        process = frame.GetThread.return_value.GetProcess.return_value
        process.ReadMemory.side_effect = lambda addr, size, err: b"a" * size
        return frame, process

    def test_filters_before_reading_memory(self):
        for field, value in (("x0", 1), ("x2", 128), ("x4", 32), ("x5", 4), ("x6", 2)):
            frame, process = self.frame(**{field: value})
            self.assertFalse(capture.pbkdf_callback(frame, None, None))
            process.ReadMemory.assert_not_called()

    def test_private_protocol_and_dedup(self):
        frame, _ = self.frame()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            capture.pbkdf_callback(frame, None, None)
            capture.pbkdf_callback(frame, None, None)
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0].removeprefix("WXEASY_KEY "))
        self.assertEqual(record, {"password": "61" * 32, "salt": "61" * 16})

    def test_rejects_short_read(self):
        frame, process = self.frame()
        process.ReadMemory.side_effect = lambda *args: b"x"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            capture.pbkdf_callback(frame, None, None)
        self.assertEqual(out.getvalue(), "")

    def test_timeout_detaches_without_relaunch(self):
        debugger = MagicMock()
        target = debugger.CreateTarget.return_value
        target.GetTriple.return_value = "arm64-apple-macosx"
        process = target.AttachToProcessWithID.return_value
        process.GetState.return_value = lldb.eStateStopped
        process.Detach.return_value.Fail.return_value = False
        with patch.dict(capture.os.environ, {"WXEASY_CAPTURE_MODE": "attach"}), \
             patch.object(capture.subprocess, "check_output", return_value="123\n"), \
             patch.object(capture.subprocess, "run") as run, \
             patch.object(capture.time, "monotonic", side_effect=[0, 121]):
            capture.capture(debugger, "", None, None)
        run.assert_not_called()
        process.Continue.assert_called_once()
        process.Stop.assert_called_once()
        target.DeleteAllBreakpoints.assert_called_once()
        process.Detach.assert_called_once()


if __name__ == "__main__":
    unittest.main()
