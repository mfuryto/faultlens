"""Real PTY lifecycle with invented collectors and UserDock-style key navigation."""
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import unittest


class WorkspacePtyTests(unittest.TestCase):
    def test_navigation_resize_and_quit_restore_terminal(self): self.exercise(False)
    def test_ctrl_c_restores_terminal(self): self.exercise(True)

    def exercise(self,interrupt):
        import fcntl
        master,slave=pty.openpty(); before=termios.tcgetattr(slave)
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',30,100,0,0))
        script='''import sys
from pathlib import Path
sys.path.insert(0,str(Path.cwd()))
from faultlens.tui import run
from tests.support import SyntheticSources,SyntheticRunner
raise SystemExit(run(sources=SyntheticSources(),runner=SyntheticRunner()))
'''
        process=subprocess.Popen([sys.executable,'-I','-B','-c',script],stdin=slave,stdout=slave,stderr=slave,
            cwd=Path(__file__).resolve().parents[1],env={**os.environ,'TERM':'xterm-256color'})
        output=bytearray()
        try:
            deadline=time.monotonic()+8
            while b'Faultlens' not in output and time.monotonic()<deadline:
                if select.select([master],[],[],0.1)[0]: output.extend(os.read(master,65536))
            self.assertIn(b'Faultlens',output)
            os.write(master,b'\x1b[C\x1b[D')
            fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',10,40,0,0)); process.send_signal(signal.SIGWINCH)
            os.write(master,b'\x03' if interrupt else b'q')
            # Drain output while waiting so terminal redraws cannot block the child.
            deadline=time.monotonic()+8
            while process.poll() is None and time.monotonic()<deadline:
                if select.select([master],[],[],0.05)[0]: os.read(master,65536)
            self.assertEqual(130 if interrupt else 0,process.wait(timeout=2))
            self.assertEqual(before,termios.tcgetattr(slave))
        finally:
            if process.poll() is None: process.kill(); process.wait()
            os.close(master); os.close(slave)


if __name__=='__main__': unittest.main()
