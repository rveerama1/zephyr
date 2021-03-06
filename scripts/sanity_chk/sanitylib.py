#!/usr/bin/env python3
# vim: set syntax=python ts=4 :
#
# Copyright (c) 2018 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

import os
import contextlib
import string
import mmap
import sys
import re
import subprocess
import select
import shutil
import shlex
import signal
import threading
import concurrent.futures
from collections import OrderedDict
from threading import BoundedSemaphore
import queue
import time
import csv
import glob
import concurrent
import xml.etree.ElementTree as ET
import logging
import pty
from pathlib import Path
import traceback
from distutils.spawn import find_executable
from colorama import Fore
import pickle
import platform
import yaml
try:
    # Use the C LibYAML parser if available, rather than the Python parser.
    # It's much faster.
    from yaml import CSafeLoader as SafeLoader
    from yaml import CDumper as Dumper
except ImportError:
    from yaml import SafeLoader, Dumper

try:
    import serial
except ImportError:
    print("Install pyserial python module with pip to use --device-testing option.")

try:
    from tabulate import tabulate
except ImportError:
    print("Install tabulate python module with pip to use --device-testing option.")

try:
    import psutil
except ImportError:
    print("Install psutil python module with pip to run in Qemu.")

ZEPHYR_BASE = os.getenv("ZEPHYR_BASE")
if not ZEPHYR_BASE:
    sys.exit("$ZEPHYR_BASE environment variable undefined")

# This is needed to load edt.pickle files.
sys.path.insert(0, os.path.join(ZEPHYR_BASE, "scripts", "dts"))
import edtlib  # pylint: disable=unused-import

hw_map_local = threading.Lock()
report_lock = threading.Lock()

# Use this for internal comparisons; that's what canonicalization is
# for. Don't use it when invoking other components of the build system
# to avoid confusing and hard to trace inconsistencies in error messages
# and logs, generated Makefiles, etc. compared to when users invoke these
# components directly.
# Note "normalization" is different from canonicalization, see os.path.
canonical_zephyr_base = os.path.realpath(ZEPHYR_BASE)

sys.path.insert(0, os.path.join(ZEPHYR_BASE, "scripts/"))

from sanity_chk import scl
from sanity_chk import expr_parser

logger = logging.getLogger('sanitycheck')
logger.setLevel(logging.DEBUG)

pipeline = queue.LifoQueue()

class CMakeCacheEntry:
    '''Represents a CMake cache entry.

    This class understands the type system in a CMakeCache.txt, and
    converts the following cache types to Python types:

    Cache Type    Python type
    ----------    -------------------------------------------
    FILEPATH      str
    PATH          str
    STRING        str OR list of str (if ';' is in the value)
    BOOL          bool
    INTERNAL      str OR list of str (if ';' is in the value)
    ----------    -------------------------------------------
    '''

    # Regular expression for a cache entry.
    #
    # CMake variable names can include escape characters, allowing a
    # wider set of names than is easy to match with a regular
    # expression. To be permissive here, use a non-greedy match up to
    # the first colon (':'). This breaks if the variable name has a
    # colon inside, but it's good enough.
    CACHE_ENTRY = re.compile(
        r'''(?P<name>.*?)                               # name
         :(?P<type>FILEPATH|PATH|STRING|BOOL|INTERNAL)  # type
         =(?P<value>.*)                                 # value
        ''', re.X)

    @classmethod
    def _to_bool(cls, val):
        # Convert a CMake BOOL string into a Python bool.
        #
        #   "True if the constant is 1, ON, YES, TRUE, Y, or a
        #   non-zero number. False if the constant is 0, OFF, NO,
        #   FALSE, N, IGNORE, NOTFOUND, the empty string, or ends in
        #   the suffix -NOTFOUND. Named boolean constants are
        #   case-insensitive. If the argument is not one of these
        #   constants, it is treated as a variable."
        #
        # https://cmake.org/cmake/help/v3.0/command/if.html
        val = val.upper()
        if val in ('ON', 'YES', 'TRUE', 'Y'):
            return 1
        elif val in ('OFF', 'NO', 'FALSE', 'N', 'IGNORE', 'NOTFOUND', ''):
            return 0
        elif val.endswith('-NOTFOUND'):
            return 0
        else:
            try:
                v = int(val)
                return v != 0
            except ValueError as exc:
                raise ValueError('invalid bool {}'.format(val)) from exc

    @classmethod
    def from_line(cls, line, line_no):
        # Comments can only occur at the beginning of a line.
        # (The value of an entry could contain a comment character).
        if line.startswith('//') or line.startswith('#'):
            return None

        # Whitespace-only lines do not contain cache entries.
        if not line.strip():
            return None

        m = cls.CACHE_ENTRY.match(line)
        if not m:
            return None

        name, type_, value = (m.group(g) for g in ('name', 'type', 'value'))
        if type_ == 'BOOL':
            try:
                value = cls._to_bool(value)
            except ValueError as exc:
                args = exc.args + ('on line {}: {}'.format(line_no, line),)
                raise ValueError(args) from exc
        elif type_ in ['STRING', 'INTERNAL']:
            # If the value is a CMake list (i.e. is a string which
            # contains a ';'), convert to a Python list.
            if ';' in value:
                value = value.split(';')

        return CMakeCacheEntry(name, value)

    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __str__(self):
        fmt = 'CMakeCacheEntry(name={}, value={})'
        return fmt.format(self.name, self.value)


class CMakeCache:
    '''Parses and represents a CMake cache file.'''

    @staticmethod
    def from_file(cache_file):
        return CMakeCache(cache_file)

    def __init__(self, cache_file):
        self.cache_file = cache_file
        self.load(cache_file)

    def load(self, cache_file):
        entries = []
        with open(cache_file, 'r') as cache:
            for line_no, line in enumerate(cache):
                entry = CMakeCacheEntry.from_line(line, line_no)
                if entry:
                    entries.append(entry)
        self._entries = OrderedDict((e.name, e) for e in entries)

    def get(self, name, default=None):
        entry = self._entries.get(name)
        if entry is not None:
            return entry.value
        else:
            return default

    def get_list(self, name, default=None):
        if default is None:
            default = []
        entry = self._entries.get(name)
        if entry is not None:
            value = entry.value
            if isinstance(value, list):
                return value
            elif isinstance(value, str):
                return [value] if value else []
            else:
                msg = 'invalid value {} type {}'
                raise RuntimeError(msg.format(value, type(value)))
        else:
            return default

    def __contains__(self, name):
        return name in self._entries

    def __getitem__(self, name):
        return self._entries[name].value

    def __setitem__(self, name, entry):
        if not isinstance(entry, CMakeCacheEntry):
            msg = 'improper type {} for value {}, expecting CMakeCacheEntry'
            raise TypeError(msg.format(type(entry), entry))
        self._entries[name] = entry

    def __delitem__(self, name):
        del self._entries[name]

    def __iter__(self):
        return iter(self._entries.values())


class SanityCheckException(Exception):
    pass


class SanityRuntimeError(SanityCheckException):
    pass


class ConfigurationError(SanityCheckException):
    def __init__(self, cfile, message):
        SanityCheckException.__init__(self, cfile + ": " + message)


class BuildError(SanityCheckException):
    pass


class ExecutionError(SanityCheckException):
    pass


class HarnessImporter:

    def __init__(self, name):
        sys.path.insert(0, os.path.join(ZEPHYR_BASE, "scripts/sanity_chk"))
        module = __import__("harness")
        if name:
            my_class = getattr(module, name)
        else:
            my_class = getattr(module, "Test")

        self.instance = my_class()


class Handler:
    def __init__(self, instance, type_str="build"):
        """Constructor

        """
        self.lock = threading.Lock()

        self.state = "waiting"
        self.run = False
        self.duration = 0
        self.type_str = type_str

        self.binary = None
        self.pid_fn = None
        self.call_make_run = False

        self.name = instance.name
        self.instance = instance
        self.timeout = instance.testcase.timeout
        self.sourcedir = instance.testcase.source_dir
        self.build_dir = instance.build_dir
        self.log = os.path.join(self.build_dir, "handler.log")
        self.returncode = 0
        self.set_state("running", self.duration)
        self.generator = None
        self.generator_cmd = None

        self.args = []

    def set_state(self, state, duration):
        self.lock.acquire()
        self.state = state
        self.duration = duration
        self.lock.release()

    def get_state(self):
        self.lock.acquire()
        ret = (self.state, self.duration)
        self.lock.release()
        return ret

    def record(self, harness):
        if harness.recording:
            filename = os.path.join(self.build_dir, "recording.csv")
            with open(filename, "at") as csvfile:
                cw = csv.writer(csvfile, harness.fieldnames, lineterminator=os.linesep)
                cw.writerow(harness.fieldnames)
                for instance in harness.recording:
                    cw.writerow(instance)


class BinaryHandler(Handler):
    def __init__(self, instance, type_str):
        """Constructor

        @param instance Test Instance
        """
        super().__init__(instance, type_str)

        self.terminated = False

        # Tool options
        self.valgrind = False
        self.lsan = False
        self.asan = False
        self.ubsan = False
        self.coverage = False

    def try_kill_process_by_pid(self):
        if self.pid_fn:
            pid = int(open(self.pid_fn).read())
            os.unlink(self.pid_fn)
            self.pid_fn = None  # clear so we don't try to kill the binary twice
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def terminate(self, proc):
        # encapsulate terminate functionality so we do it consistently where ever
        # we might want to terminate the proc.  We need try_kill_process_by_pid
        # because of both how newer ninja (1.6.0 or greater) and .NET / renode
        # work.  Newer ninja's don't seem to pass SIGTERM down to the children
        # so we need to use try_kill_process_by_pid.
        self.try_kill_process_by_pid()
        proc.terminate()
        # sleep for a while before attempting to kill
        time.sleep(0.5)
        proc.kill()
        self.terminated = True

    def _output_reader(self, proc, harness):
        log_out_fp = open(self.log, "wt")
        for line in iter(proc.stdout.readline, b''):
            logger.debug("OUTPUT: {0}".format(line.decode('utf-8').rstrip()))
            log_out_fp.write(line.decode('utf-8'))
            log_out_fp.flush()
            harness.handle(line.decode('utf-8').rstrip())
            if harness.state:
                try:
                    # POSIX arch based ztests end on their own,
                    # so let's give it up to 100ms to do so
                    proc.wait(0.1)
                except subprocess.TimeoutExpired:
                    self.terminate(proc)
                break

        log_out_fp.close()

    def handle(self):

        harness_name = self.instance.testcase.harness.capitalize()
        harness_import = HarnessImporter(harness_name)
        harness = harness_import.instance
        harness.configure(self.instance)

        if self.call_make_run:
            command = [self.generator_cmd, "run"]
        else:
            command = [self.binary]

        run_valgrind = False
        if self.valgrind and shutil.which("valgrind"):
            command = ["valgrind", "--error-exitcode=2",
                       "--leak-check=full",
                       "--suppressions=" + ZEPHYR_BASE + "/scripts/valgrind.supp",
                       "--log-file=" + self.build_dir + "/valgrind.log"
                       ] + command
            run_valgrind = True

        logger.debug("Spawning process: " +
                     " ".join(shlex.quote(word) for word in command) + os.linesep +
                     "in directory: " + self.build_dir)

        start_time = time.time()

        env = os.environ.copy()
        if self.asan:
            env["ASAN_OPTIONS"] = "log_path=stdout:" + \
                                  env.get("ASAN_OPTIONS", "")
            if not self.lsan:
                env["ASAN_OPTIONS"] += "detect_leaks=0"

        if self.ubsan:
            env["UBSAN_OPTIONS"] = "log_path=stdout:halt_on_error=1:" + \
                                  env.get("UBSAN_OPTIONS", "")

        with subprocess.Popen(command, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, cwd=self.build_dir, env=env) as proc:
            logger.debug("Spawning BinaryHandler Thread for %s" % self.name)
            t = threading.Thread(target=self._output_reader, args=(proc, harness,), daemon=True)
            t.start()
            t.join(self.timeout)
            if t.is_alive():
                self.terminate(proc)
                t.join()
            proc.wait()
            self.returncode = proc.returncode

        handler_time = time.time() - start_time

        if self.coverage:
            subprocess.call(["GCOV_PREFIX=" + self.build_dir,
                             "gcov", self.sourcedir, "-b", "-s", self.build_dir], shell=True)

        self.try_kill_process_by_pid()

        # FIXME: This is needed when killing the simulator, the console is
        # garbled and needs to be reset. Did not find a better way to do that.

        subprocess.call(["stty", "sane"])
        self.instance.results = harness.tests

        if not self.terminated and self.returncode != 0:
            # When a process is killed, the default handler returns 128 + SIGTERM
            # so in that case the return code itself is not meaningful
            self.set_state("failed", handler_time)
            self.instance.reason = "Failed"
        elif run_valgrind and self.returncode == 2:
            self.set_state("failed", handler_time)
            self.instance.reason = "Valgrind error"
        elif harness.state:
            self.set_state(harness.state, handler_time)
            if harness.state == "failed":
                self.instance.reason = "Failed"
        else:
            self.set_state("timeout", handler_time)
            self.instance.reason = "Timeout"

        self.record(harness)


class DeviceHandler(Handler):

    def __init__(self, instance, type_str):
        """Constructor

        @param instance Test Instance
        """
        super().__init__(instance, type_str)

        self.suite = None

    def monitor_serial(self, ser, halt_fileno, harness):
        log_out_fp = open(self.log, "wt")

        ser_fileno = ser.fileno()
        readlist = [halt_fileno, ser_fileno]

        while ser.isOpen():
            readable, _, _ = select.select(readlist, [], [], self.timeout)

            if halt_fileno in readable:
                logger.debug('halted')
                ser.close()
                break
            if ser_fileno not in readable:
                continue  # Timeout.

            serial_line = None
            try:
                serial_line = ser.readline()
            except TypeError:
                pass
            except serial.SerialException:
                ser.close()
                break

            # Just because ser_fileno has data doesn't mean an entire line
            # is available yet.
            if serial_line:
                sl = serial_line.decode('utf-8', 'ignore').lstrip()
                logger.debug("DEVICE: {0}".format(sl.rstrip()))

                log_out_fp.write(sl)
                log_out_fp.flush()
                harness.handle(sl.rstrip())

            if harness.state:
                ser.close()
                break

        log_out_fp.close()

    def device_is_available(self, instance):
        device = instance.platform.name
        fixture = instance.testcase.harness_config.get("fixture")
        for i in self.suite.connected_hardware:
            if fixture and fixture not in i.get('fixtures', []):
                continue
            if i['platform'] == device and i['available'] and (i['serial'] or i.get('serial_pty', None)):
                return True

        return False

    def get_available_device(self, instance):
        device = instance.platform.name
        for i in self.suite.connected_hardware:
            if i['platform'] == device and i['available'] and (i['serial'] or i.get('serial_pty', None)):
                i['available'] = False
                i['counter'] += 1
                return i

        return None

    def make_device_available(self, serial):
        with hw_map_local:
            for i in self.suite.connected_hardware:
                if i['serial'] == serial or i.get('serial_pty', None):
                    i['available'] = True

    @staticmethod
    def run_custom_script(script, timeout):
        with subprocess.Popen(script, stderr=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
            try:
                stdout, _ = proc.communicate(timeout=timeout)
                logger.debug(stdout.decode())

            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                logger.error("{} timed out".format(script))

    def handle(self):
        out_state = "failed"

        while not self.device_is_available(self.instance):
            logger.debug("Waiting for device {} to become available".format(self.instance.platform.name))
            time.sleep(1)

        hardware = self.get_available_device(self.instance)
        if hardware:
            runner = hardware.get('runner', None) or self.suite.west_runner

        serial_pty = hardware.get('serial_pty', None)
        if serial_pty:
            master, slave = pty.openpty()

            try:
                ser_pty_process = subprocess.Popen(serial_pty, stdout=master, stdin=master, stderr=master)
            except subprocess.CalledProcessError as error:
                logger.error("Failed to run subprocess {}, error {}".format(serial_pty, error.output))
                return

            serial_device = os.ttyname(slave)
        else:
            serial_device = hardware['serial']

        logger.debug("Using serial device {}".format(serial_device))

        if (self.suite.west_flash is not None) or runner:
            command = ["west", "flash", "--skip-rebuild", "-d", self.build_dir]
            command_extra_args = []

            # There are three ways this option is used.
            # 1) bare: --west-flash
            #    This results in options.west_flash == []
            # 2) with a value: --west-flash="--board-id=42"
            #    This results in options.west_flash == "--board-id=42"
            # 3) Multiple values: --west-flash="--board-id=42,--erase"
            #    This results in options.west_flash == "--board-id=42 --erase"
            if self.suite.west_flash and self.suite.west_flash != []:
                command_extra_args.extend(self.suite.west_flash.split(','))

            if runner:
                command.append("--runner")
                command.append(runner)

                board_id = hardware.get("probe_id", hardware.get("id", None))
                product = hardware.get("product", None)
                if board_id is not None:
                    if runner == "pyocd":
                        command_extra_args.append("--board-id")
                        command_extra_args.append(board_id)
                    elif runner == "nrfjprog":
                        command_extra_args.append("--snr")
                        command_extra_args.append(board_id)
                    elif runner == "openocd" and product == "STM32 STLink":
                        command_extra_args.append("--cmd-pre-init")
                        command_extra_args.append("hla_serial %s" % (board_id))
                    elif runner == "openocd" and product == "STLINK-V3":
                        command_extra_args.append("--cmd-pre-init")
                        command_extra_args.append("hla_serial %s" % (board_id))
                    elif runner == "openocd" and product == "EDBG CMSIS-DAP":
                        command_extra_args.append("--cmd-pre-init")
                        command_extra_args.append("cmsis_dap_serial %s" % (board_id))
                    elif runner == "jlink":
                        command.append("--tool-opt=-SelectEmuBySN  %s" % (board_id))

            if command_extra_args != []:
                command.append('--')
                command.extend(command_extra_args)
        else:
            command = [self.generator_cmd, "-C", self.build_dir, "flash"]

        try:
            ser = serial.Serial(
                serial_device,
                baudrate=115200,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                bytesize=serial.EIGHTBITS,
                timeout=self.timeout
            )
        except serial.SerialException as e:
            self.set_state("failed", 0)
            self.instance.reason = "Failed"
            logger.error("Serial device error: %s" % (str(e)))

            if serial_pty:
                ser_pty_process.terminate()
                outs, errs = ser_pty_process.communicate()
                logger.debug("Process {} terminated outs: {} errs {}".format(serial_pty, outs, errs))

            self.make_device_available(serial_device)
            return

        ser.flush()

        harness_name = self.instance.testcase.harness.capitalize()
        harness_import = HarnessImporter(harness_name)
        harness = harness_import.instance
        harness.configure(self.instance)
        read_pipe, write_pipe = os.pipe()
        start_time = time.time()

        pre_script = hardware.get('pre_script')
        post_flash_script = hardware.get('post_flash_script')
        post_script = hardware.get('post_script')

        if pre_script:
            self.run_custom_script(pre_script, 30)

        t = threading.Thread(target=self.monitor_serial, daemon=True,
                             args=(ser, read_pipe, harness))
        t.start()

        d_log = "{}/device.log".format(self.instance.build_dir)
        logger.debug('Flash command: %s', command)
        try:
            stdout = stderr = None
            with subprocess.Popen(command, stderr=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
                try:
                    (stdout, stderr) = proc.communicate(timeout=30)
                    logger.debug(stdout.decode())

                    if proc.returncode != 0:
                        self.instance.reason = "Device issue (Flash?)"
                        with open(d_log, "w") as dlog_fp:
                            dlog_fp.write(stderr.decode())
                except subprocess.TimeoutExpired:
                    proc.kill()
                    (stdout, stderr) = proc.communicate()
                    self.instance.reason = "Device issue (Timeout)"

            with open(d_log, "w") as dlog_fp:
                dlog_fp.write(stderr.decode())

        except subprocess.CalledProcessError:
            os.write(write_pipe, b'x')  # halt the thread

        if post_flash_script:
            self.run_custom_script(post_flash_script, 30)

        t.join(self.timeout)
        if t.is_alive():
            logger.debug("Timed out while monitoring serial output on {}".format(self.instance.platform.name))
            out_state = "timeout"

        if ser.isOpen():
            ser.close()

        if serial_pty:
            ser_pty_process.terminate()
            outs, errs = ser_pty_process.communicate()
            logger.debug("Process {} terminated outs: {} errs {}".format(serial_pty, outs, errs))

        os.close(write_pipe)
        os.close(read_pipe)

        handler_time = time.time() - start_time

        if out_state == "timeout":
            for c in self.instance.testcase.cases:
                if c not in harness.tests:
                    harness.tests[c] = "BLOCK"

            self.instance.reason = "Timeout"

        self.instance.results = harness.tests

        if harness.state:
            self.set_state(harness.state, handler_time)
            if  harness.state == "failed":
                self.instance.reason = "Failed"
        else:
            self.set_state(out_state, handler_time)

        if post_script:
            self.run_custom_script(post_script, 30)

        self.make_device_available(serial_device)

        self.record(harness)


class QEMUHandler(Handler):
    """Spawns a thread to monitor QEMU output from pipes

    We pass QEMU_PIPE to 'make run' and monitor the pipes for output.
    We need to do this as once qemu starts, it runs forever until killed.
    Test cases emit special messages to the console as they run, we check
    for these to collect whether the test passed or failed.
    """

    def __init__(self, instance, type_str):
        """Constructor

        @param instance Test instance
        """

        super().__init__(instance, type_str)
        self.fifo_fn = os.path.join(instance.build_dir, "qemu-fifo")

        self.pid_fn = os.path.join(instance.build_dir, "qemu.pid")

    @staticmethod
    def _get_cpu_time(pid):
        """get process CPU time.

        The guest virtual time in QEMU icount mode isn't host time and
        it's maintained by counting guest instructions, so we use QEMU
        process exection time to mostly simulate the time of guest OS.
        """
        proc = psutil.Process(pid)
        cpu_time = proc.cpu_times()
        return cpu_time.user + cpu_time.system

    @staticmethod
    def _thread(handler, timeout, outdir, logfile, fifo_fn, pid_fn, results, harness):
        fifo_in = fifo_fn + ".in"
        fifo_out = fifo_fn + ".out"

        # These in/out nodes are named from QEMU's perspective, not ours
        if os.path.exists(fifo_in):
            os.unlink(fifo_in)
        os.mkfifo(fifo_in)
        if os.path.exists(fifo_out):
            os.unlink(fifo_out)
        os.mkfifo(fifo_out)

        # We don't do anything with out_fp but we need to open it for
        # writing so that QEMU doesn't block, due to the way pipes work
        out_fp = open(fifo_in, "wb")
        # Disable internal buffering, we don't
        # want read() or poll() to ever block if there is data in there
        in_fp = open(fifo_out, "rb", buffering=0)
        log_out_fp = open(logfile, "wt")

        start_time = time.time()
        timeout_time = start_time + timeout
        p = select.poll()
        p.register(in_fp, select.POLLIN)
        out_state = None

        line = ""
        timeout_extended = False

        pid = 0
        if os.path.exists(pid_fn):
            pid = int(open(pid_fn).read())

        while True:
            this_timeout = int((timeout_time - time.time()) * 1000)
            if this_timeout < 0 or not p.poll(this_timeout):
                try:
                    if pid and this_timeout > 0:
                        #there's possibility we polled nothing because
                        #of not enough CPU time scheduled by host for
                        #QEMU process during p.poll(this_timeout)
                        cpu_time = QEMUHandler._get_cpu_time(pid)
                        if cpu_time < timeout and not out_state:
                            timeout_time = time.time() + (timeout - cpu_time)
                            continue
                except ProcessLookupError:
                    out_state = "failed"
                    break

                if not out_state:
                    out_state = "timeout"
                break

            if pid == 0 and os.path.exists(pid_fn):
                pid = int(open(pid_fn).read())

            try:
                c = in_fp.read(1).decode("utf-8")
            except UnicodeDecodeError:
                # Test is writing something weird, fail
                out_state = "unexpected byte"
                break

            if c == "":
                # EOF, this shouldn't happen unless QEMU crashes
                out_state = "unexpected eof"
                break
            line = line + c
            if c != "\n":
                continue

            # line contains a full line of data output from QEMU
            log_out_fp.write(line)
            log_out_fp.flush()
            line = line.strip()
            logger.debug("QEMU: %s" % line)

            harness.handle(line)
            if harness.state:
                # if we have registered a fail make sure the state is not
                # overridden by a false success message coming from the
                # testsuite
                if out_state not in ['failed', 'unexpected eof', 'unexpected byte']:
                    out_state = harness.state

                # if we get some state, that means test is doing well, we reset
                # the timeout and wait for 2 more seconds to catch anything
                # printed late. We wait much longer if code
                # coverage is enabled since dumping this information can
                # take some time.
                if not timeout_extended or harness.capture_coverage:
                    timeout_extended = True
                    if harness.capture_coverage:
                        timeout_time = time.time() + 30
                    else:
                        timeout_time = time.time() + 2
            line = ""

        handler.record(harness)

        handler_time = time.time() - start_time
        logger.debug("QEMU complete (%s) after %f seconds" %
                     (out_state, handler_time))

        if out_state == "timeout":
            handler.instance.reason = "Timeout"
            handler.set_state("failed", handler_time)
        elif out_state == "failed":
            handler.instance.reason = "Failed"
            handler.set_state("failed", handler_time)
        elif out_state in ['unexpected eof', 'unexpected byte']:
            handler.instance.reason = out_state
            handler.set_state("failed", handler_time)
        else:
            handler.set_state(out_state, handler_time)

        log_out_fp.close()
        out_fp.close()
        in_fp.close()
        if pid:
            try:
                if pid:
                    os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                # Oh well, as long as it's dead! User probably sent Ctrl-C
                pass

        os.unlink(fifo_in)
        os.unlink(fifo_out)

    def handle(self):
        self.results = {}
        self.run = True

        # We pass this to QEMU which looks for fifos with .in and .out
        # suffixes.
        self.fifo_fn = os.path.join(self.instance.build_dir, "qemu-fifo")

        self.pid_fn = os.path.join(self.instance.build_dir, "qemu.pid")
        if os.path.exists(self.pid_fn):
            os.unlink(self.pid_fn)

        self.log_fn = self.log

        harness_import = HarnessImporter(self.instance.testcase.harness.capitalize())
        harness = harness_import.instance
        harness.configure(self.instance)
        self.thread = threading.Thread(name=self.name, target=QEMUHandler._thread,
                                       args=(self, self.timeout, self.build_dir,
                                             self.log_fn, self.fifo_fn,
                                             self.pid_fn, self.results, harness))

        self.instance.results = harness.tests
        self.thread.daemon = True
        logger.debug("Spawning QEMUHandler Thread for %s" % self.name)
        self.thread.start()
        subprocess.call(["stty", "sane"])

        logger.debug("Running %s (%s)" % (self.name, self.type_str))
        command = [self.generator_cmd]
        command += ["-C", self.build_dir, "run"]

        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.build_dir) as proc:
            logger.debug("Spawning QEMUHandler Thread for %s" % self.name)
            try:
                proc.wait(self.timeout)
            except subprocess.TimeoutExpired:
                #sometimes QEMU can't handle SIGTERM signal correctly
                #in that case kill -9 QEMU process directly and leave
                #sanitycheck judge testing result by console output
                if os.path.exists(self.pid_fn):
                    qemu_pid = int(open(self.pid_fn).read())
                    try:
                        os.kill(qemu_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait()
                    if harness.state == "passed":
                        self.returncode = 0
                    else:
                        self.returncode = proc.returncode
                else:
                    proc.terminate()
                    proc.kill()
                    self.returncode = proc.returncode
            else:
                logger.debug(f"No timeout, return code from qemu: {self.returncode}")
                self.returncode = proc.returncode

            if os.path.exists(self.pid_fn):
                os.unlink(self.pid_fn)

        logger.debug(f"return code from qemu: {self.returncode}")

        if self.returncode != 0 or not harness.state:
            self.set_state("failed", 0)
            self.instance.reason = "Exited with {}".format(self.returncode)

    def get_fifo(self):
        return self.fifo_fn


class SizeCalculator:
    alloc_sections = [
        "bss",
        "noinit",
        "app_bss",
        "app_noinit",
        "ccm_bss",
        "ccm_noinit"
    ]

    rw_sections = [
        "datas",
        "initlevel",
        "exceptions",
        "initshell",
        "_static_thread_data_area",
        "k_timer_area",
        "k_mem_slab_area",
        "k_mem_pool_area",
        "sw_isr_table",
        "k_sem_area",
        "k_mutex_area",
        "app_shmem_regions",
        "_k_fifo_area",
        "_k_lifo_area",
        "k_stack_area",
        "k_msgq_area",
        "k_mbox_area",
        "k_pipe_area",
        "net_if",
        "net_if_dev",
        "net_l2_data",
        "k_queue_area",
        "_net_buf_pool_area",
        "app_datas",
        "kobject_data",
        "mmu_tables",
        "app_pad",
        "priv_stacks",
        "ccm_data",
        "usb_descriptor",
        "usb_data", "usb_bos_desc",
        "uart_mux",
        'log_backends_sections',
        'log_dynamic_sections',
        'log_const_sections',
        "app_smem",
        'shell_root_cmds_sections',
        'log_const_sections',
        "font_entry_sections",
        "priv_stacks_noinit",
        "_GCOV_BSS_SECTION_NAME",
        "gcov",
        "nocache"
    ]

    # These get copied into RAM only on non-XIP
    ro_sections = [
        "rom_start",
        "text",
        "ctors",
        "init_array",
        "reset",
        "z_object_assignment_area",
        "rodata",
        "devconfig",
        "net_l2",
        "vector",
        "sw_isr_table",
        "settings_handler_static_area",
        "bt_l2cap_fixed_chan",
        "bt_l2cap_br_fixec_chan",
        "bt_gatt_service_static",
        "vectors",
        "net_socket_register_area",
        "net_ppp_proto",
        "shell_area",
        "tracing_backend_area",
    ]

    def __init__(self, filename, extra_sections):
        """Constructor

        @param filename Path to the output binary
            The <filename> is parsed by objdump to determine section sizes
        """
        # Make sure this is an ELF binary
        with open(filename, "rb") as f:
            magic = f.read(4)

        try:
            if magic != b'\x7fELF':
                raise SanityRuntimeError("%s is not an ELF binary" % filename)
        except Exception as e:
            print(str(e))
            sys.exit(2)

        # Search for CONFIG_XIP in the ELF's list of symbols using NM and AWK.
        # GREP can not be used as it returns an error if the symbol is not
        # found.
        is_xip_command = "nm " + filename + \
                         " | awk '/CONFIG_XIP/ { print $3 }'"
        is_xip_output = subprocess.check_output(
            is_xip_command, shell=True, stderr=subprocess.STDOUT).decode(
            "utf-8").strip()
        try:
            if is_xip_output.endswith("no symbols"):
                raise SanityRuntimeError("%s has no symbol information" % filename)
        except Exception as e:
            print(str(e))
            sys.exit(2)

        self.is_xip = (len(is_xip_output) != 0)

        self.filename = filename
        self.sections = []
        self.rom_size = 0
        self.ram_size = 0
        self.extra_sections = extra_sections

        self._calculate_sizes()

    def get_ram_size(self):
        """Get the amount of RAM the application will use up on the device

        @return amount of RAM, in bytes
        """
        return self.ram_size

    def get_rom_size(self):
        """Get the size of the data that this application uses on device's flash

        @return amount of ROM, in bytes
        """
        return self.rom_size

    def unrecognized_sections(self):
        """Get a list of sections inside the binary that weren't recognized

        @return list of unrecognized section names
        """
        slist = []
        for v in self.sections:
            if not v["recognized"]:
                slist.append(v["name"])
        return slist

    def _calculate_sizes(self):
        """ Calculate RAM and ROM usage by section """
        objdump_command = "objdump -h " + self.filename
        objdump_output = subprocess.check_output(
            objdump_command, shell=True).decode("utf-8").splitlines()

        for line in objdump_output:
            words = line.split()

            if not words:  # Skip lines that are too short
                continue

            index = words[0]
            if not index[0].isdigit():  # Skip lines that do not start
                continue  # with a digit

            name = words[1]  # Skip lines with section names
            if name[0] == '.':  # starting with '.'
                continue

            # TODO this doesn't actually reflect the size in flash or RAM as
            # it doesn't include linker-imposed padding between sections.
            # It is close though.
            size = int(words[2], 16)
            if size == 0:
                continue

            load_addr = int(words[4], 16)
            virt_addr = int(words[3], 16)

            # Add section to memory use totals (for both non-XIP and XIP scenarios)
            # Unrecognized section names are not included in the calculations.
            recognized = True
            if name in SizeCalculator.alloc_sections:
                self.ram_size += size
                stype = "alloc"
            elif name in SizeCalculator.rw_sections:
                self.ram_size += size
                self.rom_size += size
                stype = "rw"
            elif name in SizeCalculator.ro_sections:
                self.rom_size += size
                if not self.is_xip:
                    self.ram_size += size
                stype = "ro"
            else:
                stype = "unknown"
                if name not in self.extra_sections:
                    recognized = False

            self.sections.append({"name": name, "load_addr": load_addr,
                                  "size": size, "virt_addr": virt_addr,
                                  "type": stype, "recognized": recognized})



class SanityConfigParser:
    """Class to read test case files with semantic checking
    """

    def __init__(self, filename, schema):
        """Instantiate a new SanityConfigParser object

        @param filename Source .yaml file to read
        """
        self.data = {}
        self.schema = schema
        self.filename = filename
        self.tests = {}
        self.common = {}

    def load(self):
        self.data = scl.yaml_load_verify(self.filename, self.schema)

        if 'tests' in self.data:
            self.tests = self.data['tests']
        if 'common' in self.data:
            self.common = self.data['common']

    def _cast_value(self, value, typestr):
        if isinstance(value, str):
            v = value.strip()
        if typestr == "str":
            return v

        elif typestr == "float":
            return float(value)

        elif typestr == "int":
            return int(value)

        elif typestr == "bool":
            return value

        elif typestr.startswith("list") and isinstance(value, list):
            return value
        elif typestr.startswith("list") and isinstance(value, str):
            vs = v.split()
            if len(typestr) > 4 and typestr[4] == ":":
                return [self._cast_value(vsi, typestr[5:]) for vsi in vs]
            else:
                return vs

        elif typestr.startswith("set"):
            vs = v.split()
            if len(typestr) > 3 and typestr[3] == ":":
                return {self._cast_value(vsi, typestr[4:]) for vsi in vs}
            else:
                return set(vs)

        elif typestr.startswith("map"):
            return value
        else:
            raise ConfigurationError(
                self.filename, "unknown type '%s'" % value)

    def get_test(self, name, valid_keys):
        """Get a dictionary representing the keys/values within a test

        @param name The test in the .yaml file to retrieve data from
        @param valid_keys A dictionary representing the intended semantics
            for this test. Each key in this dictionary is a key that could
            be specified, if a key is given in the .yaml file which isn't in
            here, it will generate an error. Each value in this dictionary
            is another dictionary containing metadata:

                "default" - Default value if not given
                "type" - Data type to convert the text value to. Simple types
                    supported are "str", "float", "int", "bool" which will get
                    converted to respective Python data types. "set" and "list"
                    may also be specified which will split the value by
                    whitespace (but keep the elements as strings). finally,
                    "list:<type>" and "set:<type>" may be given which will
                    perform a type conversion after splitting the value up.
                "required" - If true, raise an error if not defined. If false
                    and "default" isn't specified, a type conversion will be
                    done on an empty string
        @return A dictionary containing the test key-value pairs with
            type conversion and default values filled in per valid_keys
        """

        d = {}
        for k, v in self.common.items():
            d[k] = v

        for k, v in self.tests[name].items():
            if k in d:
                if isinstance(d[k], str):
                    # By default, we just concatenate string values of keys
                    # which appear both in "common" and per-test sections,
                    # but some keys are handled in adhoc way based on their
                    # semantics.
                    if k == "filter":
                        d[k] = "(%s) and (%s)" % (d[k], v)
                    else:
                        d[k] += " " + v
            else:
                d[k] = v

        for k, kinfo in valid_keys.items():
            if k not in d:
                if "required" in kinfo:
                    required = kinfo["required"]
                else:
                    required = False

                if required:
                    raise ConfigurationError(
                        self.filename,
                        "missing required value for '%s' in test '%s'" %
                        (k, name))
                else:
                    if "default" in kinfo:
                        default = kinfo["default"]
                    else:
                        default = self._cast_value("", kinfo["type"])
                    d[k] = default
            else:
                try:
                    d[k] = self._cast_value(d[k], kinfo["type"])
                except ValueError:
                    raise ConfigurationError(
                        self.filename, "bad %s value '%s' for key '%s' in name '%s'" %
                                       (kinfo["type"], d[k], k, name))

        return d


class Platform:
    """Class representing metadata for a particular platform

    Maps directly to BOARD when building"""

    platform_schema = scl.yaml_load(os.path.join(ZEPHYR_BASE,
                                                 "scripts", "sanity_chk", "platform-schema.yaml"))

    def __init__(self):
        """Constructor.

        """

        self.name = ""
        self.sanitycheck = True
        # if no RAM size is specified by the board, take a default of 128K
        self.ram = 128

        self.ignore_tags = []
        self.only_tags = []
        self.default = False
        # if no flash size is specified by the board, take a default of 512K
        self.flash = 512
        self.supported = set()

        self.arch = ""
        self.type = "na"
        self.simulation = "na"
        self.supported_toolchains = []
        self.env = []
        self.env_satisfied = True
        self.filter_data = dict()

    def load(self, platform_file):
        scp = SanityConfigParser(platform_file, self.platform_schema)
        scp.load()
        data = scp.data

        self.name = data['identifier']
        self.sanitycheck = data.get("sanitycheck", True)
        # if no RAM size is specified by the board, take a default of 128K
        self.ram = data.get("ram", 128)
        testing = data.get("testing", {})
        self.ignore_tags = testing.get("ignore_tags", [])
        self.only_tags = testing.get("only_tags", [])
        self.default = testing.get("default", False)
        # if no flash size is specified by the board, take a default of 512K
        self.flash = data.get("flash", 512)
        self.supported = set()
        for supp_feature in data.get("supported", []):
            for item in supp_feature.split(":"):
                self.supported.add(item)

        self.arch = data['arch']
        self.type = data.get('type', "na")
        self.simulation = data.get('simulation', "na")
        self.supported_toolchains = data.get("toolchain", [])
        self.env = data.get("env", [])
        self.env_satisfied = True
        for env in self.env:
            if not os.environ.get(env, None):
                self.env_satisfied = False

    def __repr__(self):
        return "<%s on %s>" % (self.name, self.arch)


class DisablePyTestCollectionMixin(object):
    __test__ = False


class TestCase(DisablePyTestCollectionMixin):
    """Class representing a test application
    """

    def __init__(self, testcase_root, workdir, name):
        """TestCase constructor.

        This gets called by TestSuite as it finds and reads test yaml files.
        Multiple TestCase instances may be generated from a single testcase.yaml,
        each one corresponds to an entry within that file.

        We need to have a unique name for every single test case. Since
        a testcase.yaml can define multiple tests, the canonical name for
        the test case is <workdir>/<name>.

        @param testcase_root os.path.abspath() of one of the --testcase-root
        @param workdir Sub-directory of testcase_root where the
            .yaml test configuration file was found
        @param name Name of this test case, corresponding to the entry name
            in the test case configuration file. For many test cases that just
            define one test, can be anything and is usually "test". This is
            really only used to distinguish between different cases when
            the testcase.yaml defines multiple tests
        """


        self.source_dir = ""
        self.yamlfile = ""
        self.cases = []
        self.name = self.get_unique(testcase_root, workdir, name)
        self.id = name

        self.type = None
        self.tags = set()
        self.extra_args = None
        self.extra_configs = None
        self.arch_whitelist = None
        self.arch_exclude = None
        self.skip = False
        self.platform_exclude = None
        self.platform_whitelist = None
        self.toolchain_exclude = None
        self.toolchain_whitelist = None
        self.tc_filter = None
        self.timeout = 60
        self.harness = ""
        self.harness_config = {}
        self.build_only = True
        self.build_on_all = False
        self.slow = False
        self.min_ram = -1
        self.depends_on = None
        self.min_flash = -1
        self.extra_sections = None
        self.integration_platforms = []

    @staticmethod
    def get_unique(testcase_root, workdir, name):

        canonical_testcase_root = os.path.realpath(testcase_root)
        if Path(canonical_zephyr_base) in Path(canonical_testcase_root).parents:
            # This is in ZEPHYR_BASE, so include path in name for uniqueness
            # FIXME: We should not depend on path of test for unique names.
            relative_tc_root = os.path.relpath(canonical_testcase_root,
                                               start=canonical_zephyr_base)
        else:
            relative_tc_root = ""

        # workdir can be "."
        unique = os.path.normpath(os.path.join(relative_tc_root, workdir, name))
        check = name.split(".")
        if len(check) < 2:
            raise SanityCheckException(f"""bad test name '{name}' in {testcase_root}/{workdir}. \
Tests should reference the category and subsystem with a dot as a separator.
                    """
                    )
        return unique

    @staticmethod
    def scan_file(inf_name):
        suite_regex = re.compile(
            # do not match until end-of-line, otherwise we won't allow
            # stc_regex below to catch the ones that are declared in the same
            # line--as we only search starting the end of this match
            br"^\s*ztest_test_suite\(\s*(?P<suite_name>[a-zA-Z0-9_]+)\s*,",
            re.MULTILINE)
        stc_regex = re.compile(
            br"^\s*"  # empy space at the beginning is ok
            # catch the case where it is declared in the same sentence, e.g:
            #
            # ztest_test_suite(mutex_complex, ztest_user_unit_test(TESTNAME));
            br"(?:ztest_test_suite\([a-zA-Z0-9_]+,\s*)?"
            # Catch ztest[_user]_unit_test-[_setup_teardown](TESTNAME)
            br"ztest_(?:1cpu_)?(?:user_)?unit_test(?:_setup_teardown)?"
            # Consume the argument that becomes the extra testcse
            br"\(\s*"
            br"(?P<stc_name>[a-zA-Z0-9_]+)"
            # _setup_teardown() variant has two extra arguments that we ignore
            br"(?:\s*,\s*[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+)?"
            br"\s*\)",
            # We don't check how it finishes; we don't care
            re.MULTILINE)
        suite_run_regex = re.compile(
            br"^\s*ztest_run_test_suite\((?P<suite_name>[a-zA-Z0-9_]+)\)",
            re.MULTILINE)
        achtung_regex = re.compile(
            br"(#ifdef|#endif)",
            re.MULTILINE)
        warnings = None

        with open(inf_name) as inf:
            if os.name == 'nt':
                mmap_args = {'fileno': inf.fileno(), 'length': 0, 'access': mmap.ACCESS_READ}
            else:
                mmap_args = {'fileno': inf.fileno(), 'length': 0, 'flags': mmap.MAP_PRIVATE, 'prot': mmap.PROT_READ,
                             'offset': 0}

            with contextlib.closing(mmap.mmap(**mmap_args)) as main_c:
                suite_regex_match = suite_regex.search(main_c)
                if not suite_regex_match:
                    # can't find ztest_test_suite, maybe a client, because
                    # it includes ztest.h
                    return None, None

                suite_run_match = suite_run_regex.search(main_c)
                if not suite_run_match:
                    raise ValueError("can't find ztest_run_test_suite")

                achtung_matches = re.findall(
                    achtung_regex,
                    main_c[suite_regex_match.end():suite_run_match.start()])
                if achtung_matches:
                    warnings = "found invalid %s in ztest_test_suite()" \
                               % ", ".join(sorted({match.decode() for match in achtung_matches},reverse = True))
                _matches = re.findall(
                    stc_regex,
                    main_c[suite_regex_match.end():suite_run_match.start()])
                for match in _matches:
                    if not match.decode().startswith("test_"):
                        warnings = "Found a test that does not start with test_"
                matches = [match.decode().replace("test_", "", 1) for match in _matches]
                return matches, warnings

    def scan_path(self, path):
        subcases = []
        for filename in glob.glob(os.path.join(path, "src", "*.c*")):
            try:
                _subcases, warnings = self.scan_file(filename)
                if warnings:
                    logger.error("%s: %s" % (filename, warnings))
                    raise SanityRuntimeError("%s: %s" % (filename, warnings))
                if _subcases:
                    subcases += _subcases
            except ValueError as e:
                logger.error("%s: can't find: %s" % (filename, e))

        for filename in glob.glob(os.path.join(path, "*.c")):
            try:
                _subcases, warnings = self.scan_file(filename)
                if warnings:
                    logger.error("%s: %s" % (filename, warnings))
                if _subcases:
                    subcases += _subcases
            except ValueError as e:
                logger.error("%s: can't find: %s" % (filename, e))
        return subcases

    def parse_subcases(self, test_path):
        results = self.scan_path(test_path)
        for sub in results:
            name = "{}.{}".format(self.id, sub)
            self.cases.append(name)

        if not results:
            self.cases.append(self.id)

    def __str__(self):
        return self.name


class TestInstance(DisablePyTestCollectionMixin):
    """Class representing the execution of a particular TestCase on a platform

    @param test The TestCase object we want to build/execute
    @param platform Platform object that we want to build and run against
    @param base_outdir Base directory for all test results. The actual
        out directory used is <outdir>/<platform>/<test case name>
    """

    def __init__(self, testcase, platform, outdir):

        self.testcase = testcase
        self.platform = platform

        self.status = None
        self.reason = "Unknown"
        self.metrics = dict()
        self.handler = None
        self.outdir = outdir

        self.name = os.path.join(platform.name, testcase.name)
        self.build_dir = os.path.join(outdir, platform.name, testcase.name)

        self.build_only = True
        self.run = False

        self.results = {}

    def __lt__(self, other):
        return self.name < other.name

    # Global testsuite parameters
    def check_build_or_run(self, build_only=False, enable_slow=False, device_testing=False, fixtures=[]):

        # right now we only support building on windows. running is still work
        # in progress.
        if os.name == 'nt':
            self.build_only = True
            self.run = False
            return

        _build_only = True

        # we asked for build-only on the command line
        if build_only or self.testcase.build_only:
            self.build_only = True
            self.run = False
            return

        # Do not run slow tests:
        skip_slow = self.testcase.slow and not enable_slow
        if skip_slow:
            self.build_only = True
            self.run = False
            return

        runnable = bool(self.testcase.type == "unit" or \
                        self.platform.type == "native" or \
                        self.platform.simulation in ["nsim", "renode", "qemu"] or \
                        device_testing)

        if self.platform.simulation == "nsim":
            if not find_executable("nsimdrv"):
                runnable = False

        if self.platform.simulation == "renode":
            if not find_executable("renode"):
                runnable = False

        # console harness allows us to run the test and capture data.
        if self.testcase.harness in [ 'console', 'ztest']:

            # if we have a fixture that is also being supplied on the
            # command-line, then we need to run the test, not just build it.
            fixture = self.testcase.harness_config.get('fixture')
            if fixture:
                if fixture in fixtures:
                    _build_only = False
                else:
                    _build_only = True
            else:
                _build_only = False

        elif self.testcase.harness:
            _build_only = True
        else:
            _build_only = False

        self.build_only = not (not _build_only and runnable)
        self.run = not self.build_only
        return

    def create_overlay(self, platform, enable_asan=False, enable_ubsan=False, enable_coverage=False, coverage_platform=[]):
        # Create this in a "sanitycheck/" subdirectory otherwise this
        # will pass this overlay to kconfig.py *twice* and kconfig.cmake
        # will silently give that second time precedence over any
        # --extra-args=CONFIG_*
        subdir = os.path.join(self.build_dir, "sanitycheck")
        os.makedirs(subdir, exist_ok=True)
        file = os.path.join(subdir, "testcase_extra.conf")

        with open(file, "w") as f:
            content = ""

            if self.testcase.extra_configs:
                content = "\n".join(self.testcase.extra_configs)

            if enable_coverage:
                if platform.name in coverage_platform:
                    content = content + "\nCONFIG_COVERAGE=y"
                    content = content + "\nCONFIG_COVERAGE_DUMP=y"

            if enable_asan:
                if platform.type == "native":
                    content = content + "\nCONFIG_ASAN=y"

            if enable_ubsan:
                if platform.type == "native":
                    content = content + "\nCONFIG_UBSAN=y"

            f.write(content)
            return content

    def calculate_sizes(self):
        """Get the RAM/ROM sizes of a test case.

        This can only be run after the instance has been executed by
        MakeGenerator, otherwise there won't be any binaries to measure.

        @return A SizeCalculator object
        """
        fns = glob.glob(os.path.join(self.build_dir, "zephyr", "*.elf"))
        fns.extend(glob.glob(os.path.join(self.build_dir, "zephyr", "*.exe")))
        fns = [x for x in fns if not x.endswith('_prebuilt.elf')]
        if len(fns) != 1:
            raise BuildError("Missing/multiple output ELF binary")

        return SizeCalculator(fns[0], self.testcase.extra_sections)

    def fill_results_by_status(self):
        """Fills results according to self.status

        The method is used to propagate the instance level status
        to the test cases inside. Useful when the whole instance is skipped
        and the info is required also at the test cases level for reporting.
        Should be used with caution, e.g. should not be used
        to fill all results with passes
        """
        status_to_verdict = {
            'skipped': 'SKIP',
            'error': 'BLOCK',
            'failure': 'FAILED'
        }

        for k in self.results:
            self.results[k] = status_to_verdict[self.status]

    def __repr__(self):
        return "<TestCase %s on %s>" % (self.testcase.name, self.platform.name)


class CMake():
    config_re = re.compile('(CONFIG_[A-Za-z0-9_]+)[=]\"?([^\"]*)\"?$')
    dt_re = re.compile('([A-Za-z0-9_]+)[=]\"?([^\"]*)\"?$')

    def __init__(self, testcase, platform, source_dir, build_dir):

        self.cwd = None
        self.capture_output = True

        self.defconfig = {}
        self.cmake_cache = {}

        self.instance = None
        self.testcase = testcase
        self.platform = platform
        self.source_dir = source_dir
        self.build_dir = build_dir
        self.log = "build.log"
        self.generator = None
        self.generator_cmd = None

    def parse_generated(self):
        self.defconfig = {}
        return {}

    def run_build(self, args=[]):

        logger.debug("Building %s for %s" % (self.source_dir, self.platform.name))

        cmake_args = []
        cmake_args.extend(args)
        cmake = shutil.which('cmake')
        cmd = [cmake] + cmake_args
        kwargs = dict()

        if self.capture_output:
            kwargs['stdout'] = subprocess.PIPE
            # CMake sends the output of message() to stderr unless it's STATUS
            kwargs['stderr'] = subprocess.STDOUT

        if self.cwd:
            kwargs['cwd'] = self.cwd

        p = subprocess.Popen(cmd, **kwargs)
        out, _ = p.communicate()

        results = {}
        if p.returncode == 0:
            msg = "Finished building %s for %s" % (self.source_dir, self.platform.name)

            self.instance.status = "passed"
            results = {'msg': msg, "returncode": p.returncode, "instance": self.instance}

            if out:
                log_msg = out.decode(sys.getdefaultencoding())
                with open(os.path.join(self.build_dir, self.log), "a") as log:
                    log.write(log_msg)

            else:
                return None
        else:
            # A real error occurred, raise an exception
            if out:
                log_msg = out.decode(sys.getdefaultencoding())
                with open(os.path.join(self.build_dir, self.log), "a") as log:
                    log.write(log_msg)

            if log_msg:
                res = re.findall("region `(FLASH|RAM|SRAM)' overflowed by", log_msg)
                if res:
                    logger.debug("Test skipped due to {} Overflow".format(res[0]))
                    self.instance.status = "skipped"
                    self.instance.reason = "{} overflow".format(res[0])
                else:
                    self.instance.status = "error"
                    self.instance.reason = "Build failure"

            results = {
                "returncode": p.returncode,
                "instance": self.instance,
            }

        return results

    def run_cmake(self, args=[]):

        if self.warnings_as_errors:
            ldflags = "-Wl,--fatal-warnings"
            cflags = "-Werror"
            aflags = "-Wa,--fatal-warnings"
        else:
            ldflags = cflags = aflags = ""

        logger.debug("Running cmake on %s for %s" % (self.source_dir, self.platform.name))
        cmake_args = [
            f'-B{self.build_dir}',
            f'-S{self.source_dir}',
            f'-DEXTRA_CFLAGS="{cflags}"',
            f'-DEXTRA_AFLAGS="{aflags}',
            f'-DEXTRA_LDFLAGS="{ldflags}"',
            f'-G{self.generator}'
        ]

        if self.cmake_only:
            cmake_args.append("-DCMAKE_EXPORT_COMPILE_COMMANDS=1")

        args = ["-D{}".format(a.replace('"', '')) for a in args]
        cmake_args.extend(args)

        cmake_opts = ['-DBOARD={}'.format(self.platform.name)]
        cmake_args.extend(cmake_opts)


        logger.debug("Calling cmake with arguments: {}".format(cmake_args))
        cmake = shutil.which('cmake')
        cmd = [cmake] + cmake_args
        kwargs = dict()

        if self.capture_output:
            kwargs['stdout'] = subprocess.PIPE
            # CMake sends the output of message() to stderr unless it's STATUS
            kwargs['stderr'] = subprocess.STDOUT

        if self.cwd:
            kwargs['cwd'] = self.cwd

        p = subprocess.Popen(cmd, **kwargs)
        out, _ = p.communicate()

        if p.returncode == 0:
            filter_results = self.parse_generated()
            msg = "Finished building %s for %s" % (self.source_dir, self.platform.name)
            logger.debug(msg)
            results = {'msg': msg, 'filter': filter_results}

        else:
            self.instance.status = "error"
            self.instance.reason = "Cmake build failure"
            logger.error("Cmake build failure: %s for %s" % (self.source_dir, self.platform.name))
            results = {"returncode": p.returncode}

        if out:
            with open(os.path.join(self.build_dir, self.log), "a") as log:
                log_msg = out.decode(sys.getdefaultencoding())
                log.write(log_msg)

        return results


class FilterBuilder(CMake):

    def __init__(self, testcase, platform, source_dir, build_dir):
        super().__init__(testcase, platform, source_dir, build_dir)

        self.log = "config-sanitycheck.log"

    def parse_generated(self):

        if self.platform.name == "unit_testing":
            return {}

        cmake_cache_path = os.path.join(self.build_dir, "CMakeCache.txt")
        defconfig_path = os.path.join(self.build_dir, "zephyr", ".config")

        with open(defconfig_path, "r") as fp:
            defconfig = {}
            for line in fp.readlines():
                m = self.config_re.match(line)
                if not m:
                    if line.strip() and not line.startswith("#"):
                        sys.stderr.write("Unrecognized line %s\n" % line)
                    continue
                defconfig[m.group(1)] = m.group(2).strip()

        self.defconfig = defconfig

        cmake_conf = {}
        try:
            cache = CMakeCache.from_file(cmake_cache_path)
        except FileNotFoundError:
            cache = {}

        for k in iter(cache):
            cmake_conf[k.name] = k.value

        self.cmake_cache = cmake_conf

        filter_data = {
            "ARCH": self.platform.arch,
            "PLATFORM": self.platform.name
        }
        filter_data.update(os.environ)
        filter_data.update(self.defconfig)
        filter_data.update(self.cmake_cache)

        edt_pickle = os.path.join(self.build_dir, "zephyr", "edt.pickle")
        if self.testcase and self.testcase.tc_filter:
            try:
                if os.path.exists(edt_pickle):
                    with open(edt_pickle, 'rb') as f:
                        edt = pickle.load(f)
                else:
                    edt = None
                res = expr_parser.parse(self.testcase.tc_filter, filter_data, edt)

            except (ValueError, SyntaxError) as se:
                sys.stderr.write(
                    "Failed processing %s\n" % self.testcase.yamlfile)
                raise se

            if not res:
                return {os.path.join(self.platform.name, self.testcase.name): True}
            else:
                return {os.path.join(self.platform.name, self.testcase.name): False}
        else:
            self.platform.filter_data = filter_data
            return filter_data


class ProjectBuilder(FilterBuilder):

    def __init__(self, suite, instance, **kwargs):
        super().__init__(instance.testcase, instance.platform, instance.testcase.source_dir, instance.build_dir)

        self.log = "build.log"
        self.instance = instance
        self.suite = suite

        self.lsan = kwargs.get('lsan', False)
        self.asan = kwargs.get('asan', False)
        self.ubsan = kwargs.get('ubsan', False)
        self.valgrind = kwargs.get('valgrind', False)
        self.extra_args = kwargs.get('extra_args', [])
        self.device_testing = kwargs.get('device_testing', False)
        self.cmake_only = kwargs.get('cmake_only', False)
        self.cleanup = kwargs.get('cleanup', False)
        self.coverage = kwargs.get('coverage', False)
        self.inline_logs = kwargs.get('inline_logs', False)
        self.generator = kwargs.get('generator', None)
        self.generator_cmd = kwargs.get('generator_cmd', None)
        self.verbose = kwargs.get('verbose', None)
        self.warnings_as_errors = kwargs.get('warnings_as_errors', True)

    @staticmethod
    def log_info(filename, inline_logs):
        filename = os.path.abspath(os.path.realpath(filename))
        if inline_logs:
            logger.info("{:-^100}".format(filename))

            try:
                with open(filename) as fp:
                    data = fp.read()
            except Exception as e:
                data = "Unable to read log data (%s)\n" % (str(e))

            logger.error(data)

            logger.info("{:-^100}".format(filename))
        else:
            logger.error("see: " + Fore.YELLOW + filename + Fore.RESET)

    def log_info_file(self, inline_logs):
        build_dir = self.instance.build_dir
        h_log = "{}/handler.log".format(build_dir)
        b_log = "{}/build.log".format(build_dir)
        v_log = "{}/valgrind.log".format(build_dir)
        d_log = "{}/device.log".format(build_dir)

        if os.path.exists(v_log) and "Valgrind" in self.instance.reason:
            self.log_info("{}".format(v_log), inline_logs)
        elif os.path.exists(h_log) and os.path.getsize(h_log) > 0:
            self.log_info("{}".format(h_log), inline_logs)
        elif os.path.exists(d_log) and os.path.getsize(d_log) > 0:
            self.log_info("{}".format(d_log), inline_logs)
        else:
            self.log_info("{}".format(b_log), inline_logs)

    def setup_handler(self):

        instance = self.instance
        args = []

        # FIXME: Needs simplification
        if instance.platform.simulation == "qemu":
            instance.handler = QEMUHandler(instance, "qemu")
            args.append("QEMU_PIPE=%s" % instance.handler.get_fifo())
            instance.handler.call_make_run = True
        elif instance.testcase.type == "unit":
            instance.handler = BinaryHandler(instance, "unit")
            instance.handler.binary = os.path.join(instance.build_dir, "testbinary")
            if self.coverage:
                args.append("COVERAGE=1")
        elif instance.platform.type == "native":
            handler = BinaryHandler(instance, "native")

            handler.asan = self.asan
            handler.valgrind = self.valgrind
            handler.lsan = self.lsan
            handler.ubsan = self.ubsan
            handler.coverage = self.coverage

            handler.binary = os.path.join(instance.build_dir, "zephyr", "zephyr.exe")
            instance.handler = handler
        elif instance.platform.simulation == "nsim":
            if find_executable("nsimdrv"):
                instance.handler = BinaryHandler(instance, "nsim")
                instance.handler.call_make_run = True
        elif instance.platform.simulation == "renode":
            if find_executable("renode"):
                instance.handler = BinaryHandler(instance, "renode")
                instance.handler.pid_fn = os.path.join(instance.build_dir, "renode.pid")
                instance.handler.call_make_run = True
        elif self.device_testing:
            instance.handler = DeviceHandler(instance, "device")

        if instance.handler:
            instance.handler.args = args
            instance.handler.generator_cmd = self.generator_cmd
            instance.handler.generator = self.generator

    def process(self, message):
        op = message.get('op')

        if not self.instance.handler:
            self.setup_handler()

        # The build process, call cmake and build with configured generator
        if op == "cmake":
            results = self.cmake()
            if self.instance.status in ["failed", "error"]:
                pipeline.put({"op": "report", "test": self.instance})
            elif self.cmake_only:
                pipeline.put({"op": "report", "test": self.instance})
            else:
                if self.instance.name in results['filter'] and results['filter'][self.instance.name]:
                    logger.debug("filtering %s" % self.instance.name)
                    self.instance.status = "skipped"
                    self.instance.reason = "filter"
                    for case in self.instance.testcase.cases:
                        self.instance.results.update({case: 'SKIP'})
                        self.suite.total_skipped_cases += 1
                    pipeline.put({"op": "report", "test": self.instance})
                else:
                    pipeline.put({"op": "build", "test": self.instance})

        elif op == "build":
            logger.debug("build test: %s" % self.instance.name)
            results = self.build()

            if not results:
                self.instance.status = "error"
                self.instance.reason = "Build Failure"
                pipeline.put({"op": "report", "test": self.instance})
            else:
                if results.get('returncode', 1) > 0:
                    pipeline.put({"op": "report", "test": self.instance})
                else:
                    if self.instance.run:
                        pipeline.put({"op": "run", "test": self.instance})
                    else:
                        pipeline.put({"op": "report", "test": self.instance})
        # Run the generated binary using one of the supported handlers
        elif op == "run":
            logger.debug("run test: %s" % self.instance.name)
            self.run()
            self.instance.status, _ = self.instance.handler.get_state()
            logger.debug(f"run status: {self.instance.status}")
            pipeline.put({
                "op": "report",
                "test": self.instance,
                "state": "executed",
                "status": self.instance.status,
                "reason": self.instance.reason}
            )

        # Report results and output progress to screen
        elif op == "report":
            with report_lock:
                self.report_out()

            if self.cleanup and not self.coverage and self.instance.status == "passed":
                pipeline.put({
                    "op": "cleanup",
                    "test": self.instance
                })

        elif op == "cleanup":
            self.cleanup_artifacts()

    def cleanup_artifacts(self):
        logger.debug("Cleaning up {}".format(self.instance.build_dir))
        whitelist = [
            'zephyr/.config',
            'handler.log',
            'build.log',
            'device.log',
            'recording.csv',
            ]
        whitelist = [os.path.join(self.instance.build_dir, file) for file in whitelist]

        for dirpath, dirnames, filenames in os.walk(self.instance.build_dir, topdown=False):
            for name in filenames:
                path = os.path.join(dirpath, name)
                if path not in whitelist:
                    os.remove(path)
            # Remove empty directories and symbolic links to directories
            for dir in dirnames:
                path = os.path.join(dirpath, dir)
                if os.path.islink(path):
                    os.remove(path)
                elif not os.listdir(path):
                    os.rmdir(path)

    def report_out(self):
        total_tests_width = len(str(self.suite.total_to_do))
        self.suite.total_done += 1
        instance = self.instance

        if instance.status in ["error", "failed", "timeout"]:
            if instance.status == "error":
                self.suite.total_errors += 1
            self.suite.total_failed += 1
            if self.verbose:
                status = Fore.RED + "FAILED " + Fore.RESET + instance.reason
            else:
                print("")
                logger.error(
                    "{:<25} {:<50} {}FAILED{}: {}".format(
                        instance.platform.name,
                        instance.testcase.name,
                        Fore.RED,
                        Fore.RESET,
                        instance.reason))
            if not self.verbose:
                self.log_info_file(self.inline_logs)
        elif instance.status == "skipped":
            self.suite.total_skipped += 1
            status = Fore.YELLOW + "SKIPPED" + Fore.RESET
        elif instance.status == "passed":
            self.suite.total_passed += 1
            status = Fore.GREEN + "PASSED" + Fore.RESET
        else:
            logger.debug(f"Unknown status = {instance.status}")
            status = Fore.YELLOW + "UNKNOWN" + Fore.RESET

        if self.verbose:
            if self.cmake_only:
                more_info = "cmake"
            elif instance.status == "skipped":
                more_info = instance.reason
            else:
                if instance.handler and instance.run:
                    more_info = instance.handler.type_str
                    htime = instance.handler.duration
                    if htime:
                        more_info += " {:.3f}s".format(htime)
                else:
                    more_info = "build"

            logger.info("{:>{}}/{} {:<25} {:<50} {} ({})".format(
                self.suite.total_done, total_tests_width, self.suite.total_to_do, instance.platform.name,
                instance.testcase.name, status, more_info))

            if instance.status in ["error", "failed", "timeout"]:
                self.log_info_file(self.inline_logs)
        else:
            sys.stdout.write("\rINFO    - Total complete: %s%4d/%4d%s  %2d%%  skipped: %s%4d%s, failed: %s%4d%s" % (
                Fore.GREEN,
                self.suite.total_done,
                self.suite.total_to_do,
                Fore.RESET,
                int((float(self.suite.total_done) / self.suite.total_to_do) * 100),
                Fore.YELLOW if self.suite.total_skipped > 0 else Fore.RESET,
                self.suite.total_skipped,
                Fore.RESET,
                Fore.RED if self.suite.total_failed > 0 else Fore.RESET,
                self.suite.total_failed,
                Fore.RESET
            )
                             )
        sys.stdout.flush()

    def cmake(self):

        instance = self.instance
        args = self.testcase.extra_args[:]
        args += self.extra_args

        if instance.handler:
            args += instance.handler.args

        # merge overlay files into one variable
        def extract_overlays(args):
            re_overlay = re.compile('OVERLAY_CONFIG=(.*)')
            other_args = []
            overlays = []
            for arg in args:
                match = re_overlay.search(arg)
                if match:
                    overlays.append(match.group(1).strip('\'"'))
                else:
                    other_args.append(arg)

            args[:] = other_args
            return overlays

        overlays = extract_overlays(args)

        if (self.testcase.extra_configs or self.coverage or
                self.asan or self.ubsan):
            overlays.append(os.path.join(instance.build_dir,
                                         "sanitycheck", "testcase_extra.conf"))

        if overlays:
            args.append("OVERLAY_CONFIG=\"%s\"" % (" ".join(overlays)))

        results = self.run_cmake(args)
        return results

    def build(self):
        results = self.run_build(['--build', self.build_dir])
        return results

    def run(self):

        instance = self.instance

        if instance.handler.type_str == "device":
            instance.handler.suite = self.suite

        instance.handler.handle()

        sys.stdout.flush()


class BoundedExecutor(concurrent.futures.ThreadPoolExecutor):
    """BoundedExecutor behaves as a ThreadPoolExecutor which will block on
    calls to submit() once the limit given as "bound" work items are queued for
    execution.
    :param bound: Integer - the maximum number of items in the work queue
    :param max_workers: Integer - the size of the thread pool
    """

    def __init__(self, bound, max_workers, **kwargs):
        super().__init__(max_workers)
        # self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.semaphore = BoundedSemaphore(bound + max_workers)

    def submit(self, fn, *args, **kwargs):
        self.semaphore.acquire()
        try:
            future = super().submit(fn, *args, **kwargs)
        except Exception:
            self.semaphore.release()
            raise
        else:
            future.add_done_callback(lambda x: self.semaphore.release())
            return future


class TestSuite(DisablePyTestCollectionMixin):
    config_re = re.compile('(CONFIG_[A-Za-z0-9_]+)[=]\"?([^\"]*)\"?$')
    dt_re = re.compile('([A-Za-z0-9_]+)[=]\"?([^\"]*)\"?$')

    tc_schema = scl.yaml_load(
        os.path.join(ZEPHYR_BASE,
                     "scripts", "sanity_chk", "testcase-schema.yaml"))

    testcase_valid_keys = {"tags": {"type": "set", "required": False},
                       "type": {"type": "str", "default": "integration"},
                       "extra_args": {"type": "list"},
                       "extra_configs": {"type": "list"},
                       "build_only": {"type": "bool", "default": False},
                       "build_on_all": {"type": "bool", "default": False},
                       "skip": {"type": "bool", "default": False},
                       "slow": {"type": "bool", "default": False},
                       "timeout": {"type": "int", "default": 60},
                       "min_ram": {"type": "int", "default": 8},
                       "depends_on": {"type": "set"},
                       "min_flash": {"type": "int", "default": 32},
                       "arch_whitelist": {"type": "set"},
                       "arch_exclude": {"type": "set"},
                       "extra_sections": {"type": "list", "default": []},
                       "integration_platforms": {"type": "list", "default": []},
                       "platform_exclude": {"type": "set"},
                       "platform_whitelist": {"type": "set"},
                       "toolchain_exclude": {"type": "set"},
                       "toolchain_whitelist": {"type": "set"},
                       "filter": {"type": "str"},
                       "harness": {"type": "str"},
                       "harness_config": {"type": "map", "default": {}}
                       }

    RELEASE_DATA = os.path.join(ZEPHYR_BASE, "scripts", "sanity_chk",
                            "sanity_last_release.csv")

    SAMPLE_FILENAME = 'sample.yaml'
    TESTCASE_FILENAME = 'testcase.yaml'

    def __init__(self, board_root_list=[], testcase_roots=[], outdir=None):

        self.roots = testcase_roots
        if not isinstance(board_root_list, list):
            self.board_roots = [board_root_list]
        else:
            self.board_roots = board_root_list

        # Testsuite Options
        self.coverage_platform = []
        self.build_only = False
        self.cmake_only = False
        self.cleanup = False
        self.enable_slow = False
        self.device_testing = False
        self.fixtures = []
        self.enable_coverage = False
        self.enable_ubsan = False
        self.enable_lsan = False
        self.enable_asan = False
        self.enable_valgrind = False
        self.extra_args = []
        self.inline_logs = False
        self.enable_sizes_report = False
        self.west_flash = None
        self.west_runner = None
        self.generator = None
        self.generator_cmd = None
        self.warnings_as_errors = True

        # Keep track of which test cases we've filtered out and why
        self.testcases = {}
        self.platforms = []
        self.selected_platforms = []
        self.default_platforms = []
        self.outdir = os.path.abspath(outdir)
        self.discards = {}
        self.load_errors = 0
        self.instances = dict()

        self.total_tests = 0  # number of test instances
        self.total_cases = 0  # number of test cases
        self.total_skipped_cases = 0  # number of skipped test cases
        self.total_done = 0  # tests completed
        self.total_failed = 0
        self.total_skipped = 0
        self.total_passed = 0
        self.total_errors = 0

        self.total_platforms = 0
        self.start_time = 0
        self.duration = 0
        self.warnings = 0
        self.cv = threading.Condition()

        # hardcoded for now
        self.connected_hardware = []

        # run integration tests only
        self.integration = False

    def get_platform_instances(self, platform):
        filtered_dict = {k:v for k,v in self.instances.items() if k.startswith(platform + "/")}
        return filtered_dict

    def config(self):
        logger.info("coverage platform: {}".format(self.coverage_platform))

    # Debug Functions
    @staticmethod
    def info(what):
        sys.stdout.write(what + "\n")
        sys.stdout.flush()

    def update(self):
        self.total_tests = len(self.instances)
        self.total_to_do = self.total_tests - self.total_skipped
        self.total_cases = 0
        for instance in self.instances:
            self.total_cases += len(self.instances[instance].testcase.cases)


    def compare_metrics(self, filename):
        # name, datatype, lower results better
        interesting_metrics = [("ram_size", int, True),
                               ("rom_size", int, True)]

        if not os.path.exists(filename):
            logger.info("Cannot compare metrics, %s not found" % filename)
            return []

        results = []
        saved_metrics = {}
        with open(filename) as fp:
            cr = csv.DictReader(fp)
            for row in cr:
                d = {}
                for m, _, _ in interesting_metrics:
                    d[m] = row[m]
                saved_metrics[(row["test"], row["platform"])] = d

        for instance in self.instances.values():
            mkey = (instance.testcase.name, instance.platform.name)
            if mkey not in saved_metrics:
                continue
            sm = saved_metrics[mkey]
            for metric, mtype, lower_better in interesting_metrics:
                if metric not in instance.metrics:
                    continue
                if sm[metric] == "":
                    continue
                delta = instance.metrics.get(metric, 0) - mtype(sm[metric])
                if delta == 0:
                    continue
                results.append((instance, metric, instance.metrics.get(metric, 0), delta,
                                lower_better))
        return results

    def misc_reports(self, report, show_footprint, all_deltas,
                     footprint_threshold, last_metrics):

        if not report:
            return

        deltas = self.compare_metrics(report)
        warnings = 0
        if deltas and show_footprint:
            for i, metric, value, delta, lower_better in deltas:
                if not all_deltas and ((delta < 0 and lower_better) or
                                       (delta > 0 and not lower_better)):
                    continue

                percentage = (float(delta) / float(value - delta))
                if not all_deltas and (percentage <
                                       (footprint_threshold / 100.0)):
                    continue

                logger.info("{:<25} {:<60} {}{}{}: {} {:<+4}, is now {:6} {:+.2%}".format(
                    i.platform.name, i.testcase.name, Fore.YELLOW,
                    "INFO" if all_deltas else "WARNING", Fore.RESET,
                    metric, delta, value, percentage))
                warnings += 1

        if warnings:
            logger.warning("Deltas based on metrics from last %s" %
                           ("release" if not last_metrics else "run"))

    def summary(self, unrecognized_sections):
        failed = 0
        run = 0
        for instance in self.instances.values():
            if instance.status == "failed":
                failed += 1
            elif instance.metrics.get("unrecognized") and not unrecognized_sections:
                logger.error("%sFAILED%s: %s has unrecognized binary sections: %s" %
                             (Fore.RED, Fore.RESET, instance.name,
                              str(instance.metrics.get("unrecognized", []))))
                failed += 1

            if instance.metrics['handler_time']:
                run += 1

        if self.total_tests and self.total_tests != self.total_skipped:
            pass_rate = (float(self.total_passed) / float(
                self.total_tests - self.total_skipped))
        else:
            pass_rate = 0

        logger.info(
            "{}{} of {}{} tests passed ({:.2%}), {}{}{} failed, {} skipped with {}{}{} warnings in {:.2f} seconds".format(
                Fore.RED if failed else Fore.GREEN,
                self.total_passed,
                self.total_tests - self.total_skipped,
                Fore.RESET,
                pass_rate,
                Fore.RED if self.total_failed else Fore.RESET,
                self.total_failed,
                Fore.RESET,
                self.total_skipped,
                Fore.YELLOW if self.warnings else Fore.RESET,
                self.warnings,
                Fore.RESET,
                self.duration))

        self.total_platforms = len(self.platforms)
        if self.platforms:
            logger.info("In total {} test cases were executed on {} out of total {} platforms ({:02.2f}%)".format(
                self.total_cases - self.total_skipped_cases,
                len(self.selected_platforms),
                self.total_platforms,
                (100 * len(self.selected_platforms) / len(self.platforms))
            ))

        logger.info(f"{Fore.GREEN}{run}{Fore.RESET} tests executed on platforms, \
{Fore.RED}{self.total_tests - run - self.total_skipped}{Fore.RESET} tests were only built.")

    def save_reports(self, name, suffix, report_dir, no_update, release, only_failed):
        if not self.instances:
            return

        if name:
            report_name = name
        else:
            report_name = "sanitycheck"

        if report_dir:
            os.makedirs(report_dir, exist_ok=True)
            filename = os.path.join(report_dir, report_name)
            outdir = report_dir
        else:
            filename = os.path.join(self.outdir, report_name)
            outdir = self.outdir

        if suffix:
            filename = "{}_{}".format(filename, suffix)

        if not no_update:
            self.xunit_report(filename + ".xml", full_report=False, append=only_failed)
            self.xunit_report(filename + "_report.xml", full_report=True, append=only_failed)
            self.csv_report(filename + ".csv")

            self.target_report(outdir, suffix, append=only_failed)
            if self.discards:
                self.discard_report(filename + "_discard.csv")

        if release:
            self.csv_report(self.RELEASE_DATA)

    def add_configurations(self):

        for board_root in self.board_roots:
            board_root = os.path.abspath(board_root)

            logger.debug("Reading platform configuration files under %s..." %
                         board_root)

            for file in glob.glob(os.path.join(board_root, "*", "*", "*.yaml")):
                logger.debug("Found platform configuration " + file)
                try:
                    platform = Platform()
                    platform.load(file)
                    if platform.sanitycheck:
                        self.platforms.append(platform)
                        if platform.default:
                            self.default_platforms.append(platform.name)

                except RuntimeError as e:
                    logger.error("E: %s: can't load: %s" % (file, e))
                    self.load_errors += 1

    def get_all_tests(self):
        tests = []
        for _, tc in self.testcases.items():
            for case in tc.cases:
                tests.append(case)

        return tests

    @staticmethod
    def get_toolchain():
        toolchain = os.environ.get("ZEPHYR_TOOLCHAIN_VARIANT", None) or \
                    os.environ.get("ZEPHYR_GCC_VARIANT", None)

        if toolchain == "gccarmemb":
            # Remove this translation when gccarmemb is no longer supported.
            toolchain = "gnuarmemb"

        try:
            if not toolchain:
                raise SanityRuntimeError("E: Variable ZEPHYR_TOOLCHAIN_VARIANT is not defined")
        except Exception as e:
            print(str(e))
            sys.exit(2)

        return toolchain

    def add_testcases(self, testcase_filter=[]):
        for root in self.roots:
            root = os.path.abspath(root)

            logger.debug("Reading test case configuration files under %s..." % root)

            for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                logger.debug("scanning %s" % dirpath)
                if self.SAMPLE_FILENAME in filenames:
                    filename = self.SAMPLE_FILENAME
                elif self.TESTCASE_FILENAME in filenames:
                    filename = self.TESTCASE_FILENAME
                else:
                    continue

                logger.debug("Found possible test case in " + dirpath)

                dirnames[:] = []
                tc_path = os.path.join(dirpath, filename)

                try:
                    parsed_data = SanityConfigParser(tc_path, self.tc_schema)
                    parsed_data.load()

                    tc_path = os.path.dirname(tc_path)
                    workdir = os.path.relpath(tc_path, root)

                    for name in parsed_data.tests.keys():
                        tc = TestCase(root, workdir, name)

                        tc_dict = parsed_data.get_test(name, self.testcase_valid_keys)

                        tc.source_dir = tc_path
                        tc.yamlfile = tc_path

                        tc.type = tc_dict["type"]
                        tc.tags = tc_dict["tags"]
                        tc.extra_args = tc_dict["extra_args"]
                        tc.extra_configs = tc_dict["extra_configs"]
                        tc.arch_whitelist = tc_dict["arch_whitelist"]
                        tc.arch_exclude = tc_dict["arch_exclude"]
                        tc.skip = tc_dict["skip"]
                        tc.platform_exclude = tc_dict["platform_exclude"]
                        tc.platform_whitelist = tc_dict["platform_whitelist"]
                        tc.toolchain_exclude = tc_dict["toolchain_exclude"]
                        tc.toolchain_whitelist = tc_dict["toolchain_whitelist"]
                        tc.tc_filter = tc_dict["filter"]
                        tc.timeout = tc_dict["timeout"]
                        tc.harness = tc_dict["harness"]
                        tc.harness_config = tc_dict["harness_config"]
                        if tc.harness == 'console' and not tc.harness_config:
                            raise Exception('Harness config error: console harness defined without a configuration.')
                        tc.build_only = tc_dict["build_only"]
                        tc.build_on_all = tc_dict["build_on_all"]
                        tc.slow = tc_dict["slow"]
                        tc.min_ram = tc_dict["min_ram"]
                        tc.depends_on = tc_dict["depends_on"]
                        tc.min_flash = tc_dict["min_flash"]
                        tc.extra_sections = tc_dict["extra_sections"]
                        tc.integration_platforms = tc_dict["integration_platforms"]

                        tc.parse_subcases(tc_path)

                        if testcase_filter:
                            if tc.name and tc.name in testcase_filter:
                                self.testcases[tc.name] = tc
                        else:
                            self.testcases[tc.name] = tc

                except Exception as e:
                    logger.error("%s: can't load (skipping): %s" % (tc_path, e))
                    self.load_errors += 1


    def get_platform(self, name):
        selected_platform = None
        for platform in self.platforms:
            if platform.name == name:
                selected_platform = platform
                break
        return selected_platform

    def load_from_file(self, file, filter_status=[]):
        try:
            with open(file, "r") as fp:
                cr = csv.DictReader(fp)
                instance_list = []
                for row in cr:
                    if row["status"] in filter_status:
                        continue
                    test = row["test"]

                    platform = self.get_platform(row["platform"])
                    instance = TestInstance(self.testcases[test], platform, self.outdir)
                    instance.check_build_or_run(
                        self.build_only,
                        self.enable_slow,
                        self.device_testing,
                        self.fixtures
                    )
                    instance.create_overlay(platform, self.enable_asan, self.enable_ubsan, self.enable_coverage, self.coverage_platform)
                    instance_list.append(instance)
                self.add_instances(instance_list)

        except KeyError as e:
            logger.error("Key error while parsing tests file.({})".format(str(e)))
            sys.exit(2)

        except FileNotFoundError as e:
            logger.error("Couldn't find input file with list of tests. ({})".format(e))
            sys.exit(2)

    def apply_filters(self, **kwargs):

        toolchain = self.get_toolchain()

        discards = {}
        platform_filter = kwargs.get('platform')
        exclude_platform = kwargs.get('exclude_platform', [])
        testcase_filter = kwargs.get('run_individual_tests', [])
        arch_filter = kwargs.get('arch')
        tag_filter = kwargs.get('tag')
        exclude_tag = kwargs.get('exclude_tag')
        all_filter = kwargs.get('all')
        device_testing_filter = kwargs.get('device_testing')
        force_toolchain = kwargs.get('force_toolchain')
        force_platform = kwargs.get('force_platform')

        logger.debug("platform filter: " + str(platform_filter))
        logger.debug("    arch_filter: " + str(arch_filter))
        logger.debug("     tag_filter: " + str(tag_filter))
        logger.debug("    exclude_tag: " + str(exclude_tag))

        default_platforms = False

        if platform_filter:
            platforms = list(filter(lambda p: p.name in platform_filter, self.platforms))
        else:
            platforms = self.platforms

        if all_filter:
            logger.info("Selecting all possible platforms per test case")
            # When --all used, any --platform arguments ignored
            platform_filter = []
        elif not platform_filter:
            logger.info("Selecting default platforms per test case")
            default_platforms = True

        logger.info("Building initial testcase list...")

        for tc_name, tc in self.testcases.items():
            # list of instances per testcase, aka configurations.
            instance_list = []
            for plat in platforms:
                instance = TestInstance(tc, plat, self.outdir)
                instance.check_build_or_run(
                    self.build_only,
                    self.enable_slow,
                    self.device_testing,
                    self.fixtures
                )
                for t in tc.cases:
                    instance.results[t] = None

                if device_testing_filter:
                    for h in self.connected_hardware:
                        if h['platform'] == plat.name:
                            if tc.harness_config.get('fixture') in h.get('fixtures', []):
                                instance.build_only = False
                                instance.run = True

                if not force_platform and plat.name in exclude_platform:
                    discards[instance] = discards.get(instance, "Platform is excluded on command line.")

                if (plat.arch == "unit") != (tc.type == "unit"):
                    # Discard silently
                    continue

                if device_testing_filter and instance.build_only:
                    discards[instance] = discards.get(instance, "Not runnable on device")

                if self.integration and tc.integration_platforms and plat.name not in tc.integration_platforms:
                    discards[instance] = discards.get(instance, "Not part of integration platforms")

                if tc.skip:
                    discards[instance] = discards.get(instance, "Skip filter")

                if tc.build_on_all and not platform_filter:
                    platform_filter = []

                if tag_filter and not tc.tags.intersection(tag_filter):
                    discards[instance] = discards.get(instance, "Command line testcase tag filter")

                if exclude_tag and tc.tags.intersection(exclude_tag):
                    discards[instance] = discards.get(instance, "Command line testcase exclude filter")

                if testcase_filter and tc_name not in testcase_filter:
                    discards[instance] = discards.get(instance, "Testcase name filter")

                if arch_filter and plat.arch not in arch_filter:
                    discards[instance] = discards.get(instance, "Command line testcase arch filter")

                if not force_platform:

                    if tc.arch_whitelist and plat.arch not in tc.arch_whitelist:
                        discards[instance] = discards.get(instance, "Not in test case arch whitelist")

                    if tc.arch_exclude and plat.arch in tc.arch_exclude:
                        discards[instance] = discards.get(instance, "In test case arch exclude")

                    if tc.platform_exclude and plat.name in tc.platform_exclude:
                        discards[instance] = discards.get(instance, "In test case platform exclude")

                if tc.toolchain_exclude and toolchain in tc.toolchain_exclude:
                    discards[instance] = discards.get(instance, "In test case toolchain exclude")

                if platform_filter and plat.name not in platform_filter:
                    discards[instance] = discards.get(instance, "Command line platform filter")

                if tc.platform_whitelist and plat.name not in tc.platform_whitelist:
                    discards[instance] = discards.get(instance, "Not in testcase platform whitelist")

                if tc.toolchain_whitelist and toolchain not in tc.toolchain_whitelist:
                    discards[instance] = discards.get(instance, "Not in testcase toolchain whitelist")

                if not plat.env_satisfied:
                    discards[instance] = discards.get(instance, "Environment ({}) not satisfied".format(", ".join(plat.env)))

                if not force_toolchain \
                        and toolchain and (toolchain not in plat.supported_toolchains) \
                        and tc.type != 'unit':
                    discards[instance] = discards.get(instance, "Not supported by the toolchain")

                if plat.ram < tc.min_ram:
                    discards[instance] = discards.get(instance, "Not enough RAM")

                if tc.depends_on:
                    dep_intersection = tc.depends_on.intersection(set(plat.supported))
                    if dep_intersection != set(tc.depends_on):
                        discards[instance] = discards.get(instance, "No hardware support")

                if plat.flash < tc.min_flash:
                    discards[instance] = discards.get(instance, "Not enough FLASH")

                if set(plat.ignore_tags) & tc.tags:
                    discards[instance] = discards.get(instance, "Excluded tags per platform (exclude_tags)")

                if plat.only_tags and not set(plat.only_tags) & tc.tags:
                    discards[instance] = discards.get(instance, "Excluded tags per platform (only_tags)")

                # if nothing stopped us until now, it means this configuration
                # needs to be added.
                instance_list.append(instance)

            # no configurations, so jump to next testcase
            if not instance_list:
                continue

            # if sanitycheck was launched with no platform options at all, we
            # take all default platforms
            if default_platforms and not tc.build_on_all:
                if tc.platform_whitelist:
                    a = set(self.default_platforms)
                    b = set(tc.platform_whitelist)
                    c = a.intersection(b)
                    if c:
                        aa = list(filter(lambda tc: tc.platform.name in c, instance_list))
                        self.add_instances(aa)
                    else:
                        self.add_instances(instance_list[:1])
                else:
                    instances = list(filter(lambda tc: tc.platform.default, instance_list))
                    self.add_instances(instances)

                for instance in list(filter(lambda inst: not inst.platform.default, instance_list)):
                    discards[instance] = discards.get(instance, "Not a default test platform")

            else:
                self.add_instances(instance_list)

        for _, case in self.instances.items():
            case.create_overlay(case.platform, self.enable_asan, self.enable_ubsan, self.enable_coverage, self.coverage_platform)

        self.discards = discards
        self.selected_platforms = set(p.platform.name for p in self.instances.values())

        for instance in self.discards:
            instance.reason = self.discards[instance]
            instance.status = "skipped"
            instance.fill_results_by_status()
            # We only count skipped tests for instances in self.instances
            if self.instances.get(instance.name, False):
                self.total_skipped += 1
                self.total_skipped_cases += len(instance.testcase.cases)

        return discards

    def add_instances(self, instance_list):
        for instance in instance_list:
            self.instances[instance.name] = instance

    def add_tasks_to_queue(self, test_only=False):
        for instance in self.instances.values():
            if test_only:
                if instance.run:
                    pipeline.put({"op": "run", "test": instance, "status": "built"})
            else:
                if instance.status not in ['passed', 'skipped', 'error']:
                    instance.status = None
                    pipeline.put({"op": "cmake", "test": instance})

        return "DONE FEEDING"

    def execute(self):

        def calc_one_elf_size(instance):
            if instance.status not in ["error", "failed", "skipped"]:
                if instance.platform.type != "native":
                    size_calc = instance.calculate_sizes()
                    instance.metrics["ram_size"] = size_calc.get_ram_size()
                    instance.metrics["rom_size"] = size_calc.get_rom_size()
                    instance.metrics["unrecognized"] = size_calc.unrecognized_sections()
                else:
                    instance.metrics["ram_size"] = 0
                    instance.metrics["rom_size"] = 0
                    instance.metrics["unrecognized"] = []

                instance.metrics["handler_time"] = instance.handler.duration if instance.handler else 0

        logger.info("Adding tasks to the queue...")
        # We can use a with statement to ensure threads are cleaned up promptly
        with BoundedExecutor(bound=self.jobs, max_workers=self.jobs) as executor:

            # start a future for a thread which sends work in through the queue
            future_to_test = {
                executor.submit(self.add_tasks_to_queue, self.test_only): 'FEEDER DONE'}

            while future_to_test:
                # check for status of the futures which are currently working
                done, pending = concurrent.futures.wait(future_to_test, timeout=1,
                    return_when=concurrent.futures.FIRST_COMPLETED)

                # if there is incoming work, start a new future
                while not pipeline.empty():
                    # fetch a url from the queue
                    message = pipeline.get()
                    test = message['test']

                    pb = ProjectBuilder(self,
                                        test,
                                        lsan=self.enable_lsan,
                                        asan=self.enable_asan,
                                        ubsan=self.enable_ubsan,
                                        coverage=self.enable_coverage,
                                        extra_args=self.extra_args,
                                        device_testing=self.device_testing,
                                        cmake_only=self.cmake_only,
                                        cleanup=self.cleanup,
                                        valgrind=self.enable_valgrind,
                                        inline_logs=self.inline_logs,
                                        generator=self.generator,
                                        generator_cmd=self.generator_cmd,
                                        verbose=self.verbose,
                                        warnings_as_errors=self.warnings_as_errors
                                        )
                    future_to_test[executor.submit(pb.process, message)] = test.name

                # process any completed futures
                for future in done:
                    test = future_to_test[future]
                    try:
                        data = future.result()
                    except Exception as exc:
                        logger.error('%r generated an exception:' % (test,))
                        for line in traceback.format_exc().splitlines():
                            logger.error(line)
                        sys.exit('%r generated an exception: %s' % (test, exc))

                    else:
                        if data:
                            logger.debug(data)

                    # remove the now completed future
                    del future_to_test[future]

                for future in pending:
                    test = future_to_test[future]

                    try:
                        future.result(timeout=180)
                    except concurrent.futures.TimeoutError:
                        logger.warning("{} stuck?".format(test))

        if self.enable_size_report and not self.cmake_only:
            # Parallelize size calculation
            executor = concurrent.futures.ThreadPoolExecutor(self.jobs)
            futures = [executor.submit(calc_one_elf_size, instance)
                       for instance in self.instances.values()]
            concurrent.futures.wait(futures)
        else:
            for instance in self.instances.values():
                instance.metrics["ram_size"] = 0
                instance.metrics["rom_size"] = 0
                instance.metrics["handler_time"] = instance.handler.duration if instance.handler else 0
                instance.metrics["unrecognized"] = []

    def discard_report(self, filename):

        try:
            if not self.discards:
                raise SanityRuntimeError("apply_filters() hasn't been run!")
        except Exception as e:
            logger.error(str(e))
            sys.exit(2)

        with open(filename, "wt") as csvfile:
            fieldnames = ["test", "arch", "platform", "reason"]
            cw = csv.DictWriter(csvfile, fieldnames, lineterminator=os.linesep)
            cw.writeheader()
            for instance, reason in sorted(self.discards.items()):
                rowdict = {"test": instance.testcase.name,
                           "arch": instance.platform.arch,
                           "platform": instance.platform.name,
                           "reason": reason}
                cw.writerow(rowdict)

    def target_report(self, outdir, suffix, append=False):
        platforms = {inst.platform.name for _, inst in self.instances.items()}
        for platform in platforms:
            if suffix:
                filename = os.path.join(outdir,"{}_{}.xml".format(platform, suffix))
            else:
                filename = os.path.join(outdir,"{}.xml".format(platform))
            self.xunit_report(filename, platform, full_report=True, append=append)


    @staticmethod
    def process_log(log_file):
        filtered_string = ""
        if os.path.exists(log_file):
            with open(log_file, "rb") as f:
                log = f.read().decode("utf-8")
                filtered_string = ''.join(filter(lambda x: x in string.printable, log))

        return filtered_string


    def xunit_report(self, filename, platform=None, full_report=False, append=False):
        total = 0
        if platform:
            selected = [platform]
        else:
            selected = self.selected_platforms

        if os.path.exists(filename) and append:
            tree = ET.parse(filename)
            eleTestsuites = tree.getroot()
        else:
            eleTestsuites = ET.Element('testsuites')

        for p in selected:
            inst = self.get_platform_instances(p)
            fails = 0
            passes = 0
            errors = 0
            skips = 0
            duration = 0

            for _, instance in inst.items():
                handler_time = instance.metrics.get('handler_time', 0)
                duration += handler_time
                if full_report and not instance.build_only:
                    for k in instance.results.keys():
                        if instance.results[k] == 'PASS':
                            passes += 1
                        elif instance.results[k] == 'BLOCK':
                            errors += 1
                        elif instance.results[k] == 'SKIP':
                            skips += 1
                        else:
                            fails += 1
                else:
                    if instance.status in ["error", "failed", "timeout"]:
                        if instance.reason in ['build_error', 'handler_crash']:
                            errors += 1
                        else:
                            fails += 1
                    elif instance.status == 'skipped':
                        skips += 1
                    elif instance.status == 'passed':
                        passes += 1
                    else:
                        logger.error(f"Unknown status {instance.status}")

            total = (errors + passes + fails + skips)
            # do not produce a report if no tests were actually run (only built)
            if total == 0:
                continue

            run = p
            eleTestsuite = None

            # When we re-run the tests, we re-use the results and update only with
            # the newly run tests.
            if os.path.exists(filename) and append:
                ts = eleTestsuites.findall(f'testsuite/[@name="{p}"]')
                if ts:
                    eleTestsuite = ts[0]
                    eleTestsuite.attrib['failures'] = "%d" % fails
                    eleTestsuite.attrib['errors'] = "%d" % errors
                    eleTestsuite.attrib['skip'] = "%d" % skips
                else:
                    logger.info(f"Did not find any existing results for {p}")
                    eleTestsuite = ET.SubElement(eleTestsuites, 'testsuite',
                                name=run, time="%f" % duration,
                                tests="%d" % (total),
                                failures="%d" % fails,
                                errors="%d" % (errors), skip="%s" % (skips))

            else:
                eleTestsuite = ET.SubElement(eleTestsuites, 'testsuite',
                                             name=run, time="%f" % duration,
                                             tests="%d" % (total),
                                             failures="%d" % fails,
                                             errors="%d" % (errors), skip="%s" % (skips))

            for _, instance in inst.items():
                if full_report:
                    tname = os.path.basename(instance.testcase.name)
                else:
                    tname = instance.testcase.id


                handler_time = instance.metrics.get('handler_time', 0)

                if full_report:
                    for k in instance.results.keys():
                        # remove testcases that are being re-run from exiting reports
                        for tc in eleTestsuite.findall(f'testcase/[@name="{k}"]'):
                            eleTestsuite.remove(tc)

                        classname = ".".join(tname.split(".")[:2])
                        eleTestcase = ET.SubElement(
                            eleTestsuite, 'testcase',
                            classname=classname,
                            name="%s" % (k), time="%f" % handler_time)

                        if instance.results[k] in ['FAIL', 'BLOCK'] or \
                            (instance.build_only and instance.status in ["error", "failed", "timeout"]):
                            if instance.results[k] == 'FAIL':
                                el = ET.SubElement(
                                    eleTestcase,
                                    'failure',
                                    type="failure",
                                    message="failed")
                            else:
                                el = ET.SubElement(
                                    eleTestcase,
                                    'error',
                                    type="failure",
                                    message="failed")
                            p = os.path.join(self.outdir, instance.platform.name, instance.testcase.name)
                            log_file = os.path.join(p, "handler.log")
                            el.text = self.process_log(log_file)

                        elif instance.results[k] == 'PASS' \
                            or (instance.build_only and instance.status in ["passed"]):
                            pass
                        elif instance.results[k] == 'SKIP' \
                            or (instance.build_only and instance.status in ["skipped"]):
                            el = ET.SubElement(eleTestcase, 'skipped', type="skipped", message=instance.reason)
                        else:
                            el = ET.SubElement(
                                eleTestcase,
                                'error',
                                type="error",
                                message=f"{instance.reason}")
                else:
                    if platform:
                        classname = ".".join(instance.testcase.name.split(".")[:2])
                    else:
                        classname = p + ":" + ".".join(instance.testcase.name.split(".")[:2])

                    # remove testcases that are being re-run from exiting reports
                    for tc in eleTestsuite.findall(f'testcase/[@classname="{classname}"]'):
                        eleTestsuite.remove(tc)

                    eleTestcase = ET.SubElement(eleTestsuite, 'testcase',
                        classname=classname,
                        name="%s" % (instance.testcase.name),
                        time="%f" % handler_time)

                    if instance.status in ["error", "failed", "timeout"]:
                        failure = ET.SubElement(
                            eleTestcase,
                            'failure',
                            type="failure",
                            message=instance.reason)

                        p = ("%s/%s/%s" % (self.outdir, instance.platform.name, instance.testcase.name))
                        bl = os.path.join(p, "build.log")
                        hl = os.path.join(p, "handler.log")
                        log_file = bl
                        if instance.reason != 'Build error':
                            if os.path.exists(hl):
                                log_file = hl
                            else:
                                log_file = bl

                        failure.text = self.process_log(log_file)

                    elif instance.status == "skipped":
                        ET.SubElement(eleTestcase, 'skipped', type="skipped", message="Skipped")

        result = ET.tostring(eleTestsuites)
        with open(filename, 'wb') as report:
            report.write(result)

        return fails, passes, errors, skips

    def csv_report(self, filename):
        with open(filename, "wt") as csvfile:
            fieldnames = ["test", "arch", "platform", "status",
                          "extra_args", "handler", "handler_time", "ram_size",
                          "rom_size"]
            cw = csv.DictWriter(csvfile, fieldnames, lineterminator=os.linesep)
            cw.writeheader()
            for instance in self.instances.values():
                rowdict = {"test": instance.testcase.name,
                           "arch": instance.platform.arch,
                           "platform": instance.platform.name,
                           "extra_args": " ".join(instance.testcase.extra_args),
                           "handler": instance.platform.simulation}

                rowdict["status"] = instance.status
                if instance.status not in ["error", "failed", "timeout"]:
                    if instance.handler:
                        rowdict["handler_time"] = instance.metrics.get("handler_time", 0)
                    ram_size = instance.metrics.get("ram_size", 0)
                    rom_size = instance.metrics.get("rom_size", 0)
                    rowdict["ram_size"] = ram_size
                    rowdict["rom_size"] = rom_size
                cw.writerow(rowdict)

    def get_testcase(self, identifier):
        results = []
        for _, tc in self.testcases.items():
            for case in tc.cases:
                if case == identifier:
                    results.append(tc)
        return results


class CoverageTool:
    """ Base class for every supported coverage tool
    """

    def __init__(self):
        self.gcov_tool = None
        self.base_dir = None

    @staticmethod
    def factory(tool):
        if tool == 'lcov':
            t =  Lcov()
        elif tool == 'gcovr':
            t =  Lcov()
        else:
            logger.error("Unsupported coverage tool specified: {}".format(tool))
            return None

        return t

    @staticmethod
    def retrieve_gcov_data(intput_file):
        logger.debug("Working on %s" % intput_file)
        extracted_coverage_info = {}
        capture_data = False
        capture_complete = False
        with open(intput_file, 'r') as fp:
            for line in fp.readlines():
                if re.search("GCOV_COVERAGE_DUMP_START", line):
                    capture_data = True
                    continue
                if re.search("GCOV_COVERAGE_DUMP_END", line):
                    capture_complete = True
                    break
                # Loop until the coverage data is found.
                if not capture_data:
                    continue
                if line.startswith("*"):
                    sp = line.split("<")
                    if len(sp) > 1:
                        # Remove the leading delimiter "*"
                        file_name = sp[0][1:]
                        # Remove the trailing new line char
                        hex_dump = sp[1][:-1]
                    else:
                        continue
                else:
                    continue
                extracted_coverage_info.update({file_name: hex_dump})
        if not capture_data:
            capture_complete = True
        return {'complete': capture_complete, 'data': extracted_coverage_info}

    @staticmethod
    def create_gcda_files(extracted_coverage_info):
        logger.debug("Generating gcda files")
        for filename, hexdump_val in extracted_coverage_info.items():
            # if kobject_hash is given for coverage gcovr fails
            # hence skipping it problem only in gcovr v4.1
            if "kobject_hash" in filename:
                filename = (filename[:-4]) + "gcno"
                try:
                    os.remove(filename)
                except Exception:
                    pass
                continue

            with open(filename, 'wb') as fp:
                fp.write(bytes.fromhex(hexdump_val))

    def generate(self, outdir):
        for filename in glob.glob("%s/**/handler.log" % outdir, recursive=True):
            gcov_data = self.__class__.retrieve_gcov_data(filename)
            capture_complete = gcov_data['complete']
            extracted_coverage_info = gcov_data['data']
            if capture_complete:
                self.__class__.create_gcda_files(extracted_coverage_info)
                logger.debug("Gcov data captured: {}".format(filename))
            else:
                logger.error("Gcov data capture incomplete: {}".format(filename))

        with open(os.path.join(outdir, "coverage.log"), "a") as coveragelog:
            ret = self._generate(outdir, coveragelog)
            if ret == 0:
                logger.info("HTML report generated: {}".format(
                    os.path.join(outdir, "coverage", "index.html")))


class Lcov(CoverageTool):

    def __init__(self):
        super().__init__()
        self.ignores = []

    def add_ignore_file(self, pattern):
        self.ignores.append('*' + pattern + '*')

    def add_ignore_directory(self, pattern):
        self.ignores.append(pattern + '/*')

    def _generate(self, outdir, coveragelog):
        coveragefile = os.path.join(outdir, "coverage.info")
        ztestfile = os.path.join(outdir, "ztest.info")
        subprocess.call(["lcov", "--gcov-tool", self.gcov_tool,
                         "--capture", "--directory", outdir,
                         "--rc", "lcov_branch_coverage=1",
                         "--output-file", coveragefile], stdout=coveragelog)
        # We want to remove tests/* and tests/ztest/test/* but save tests/ztest
        subprocess.call(["lcov", "--gcov-tool", self.gcov_tool, "--extract",
                         coveragefile,
                         os.path.join(self.base_dir, "tests", "ztest", "*"),
                         "--output-file", ztestfile,
                         "--rc", "lcov_branch_coverage=1"], stdout=coveragelog)

        if os.path.exists(ztestfile) and os.path.getsize(ztestfile) > 0:
            subprocess.call(["lcov", "--gcov-tool", self.gcov_tool, "--remove",
                             ztestfile,
                             os.path.join(self.base_dir, "tests/ztest/test/*"),
                             "--output-file", ztestfile,
                             "--rc", "lcov_branch_coverage=1"],
                            stdout=coveragelog)
            files = [coveragefile, ztestfile]
        else:
            files = [coveragefile]

        for i in self.ignores:
            subprocess.call(
                ["lcov", "--gcov-tool", self.gcov_tool, "--remove",
                 coveragefile, i, "--output-file",
                 coveragefile, "--rc", "lcov_branch_coverage=1"],
                stdout=coveragelog)

        # The --ignore-errors source option is added to avoid it exiting due to
        # samples/application_development/external_lib/
        return subprocess.call(["genhtml", "--legend", "--branch-coverage",
                                "--ignore-errors", "source",
                                "-output-directory",
                                os.path.join(outdir, "coverage")] + files,
                               stdout=coveragelog)


class Gcovr(CoverageTool):

    def __init__(self):
        super().__init__()
        self.ignores = []

    def add_ignore_file(self, pattern):
        self.ignores.append('.*' + pattern + '.*')

    def add_ignore_directory(self, pattern):
        self.ignores.append(pattern + '/.*')

    @staticmethod
    def _interleave_list(prefix, list):
        tuple_list = [(prefix, item) for item in list]
        return [item for sublist in tuple_list for item in sublist]

    def _generate(self, outdir, coveragelog):
        coveragefile = os.path.join(outdir, "coverage.json")
        ztestfile = os.path.join(outdir, "ztest.json")

        excludes = Gcovr._interleave_list("-e", self.ignores)

        # We want to remove tests/* and tests/ztest/test/* but save tests/ztest
        subprocess.call(["gcovr", "-r", self.base_dir, "--gcov-executable",
                         self.gcov_tool, "-e", "tests/*"] + excludes +
                        ["--json", "-o", coveragefile, outdir],
                        stdout=coveragelog)

        subprocess.call(["gcovr", "-r", self.base_dir, "--gcov-executable",
                         self.gcov_tool, "-f", "tests/ztest", "-e",
                         "tests/ztest/test/*", "--json", "-o", ztestfile,
                         outdir], stdout=coveragelog)

        if os.path.exists(ztestfile) and os.path.getsize(ztestfile) > 0:
            files = [coveragefile, ztestfile]
        else:
            files = [coveragefile]

        subdir = os.path.join(outdir, "coverage")
        os.makedirs(subdir, exist_ok=True)

        tracefiles = self._interleave_list("--add-tracefile", files)

        return subprocess.call(["gcovr", "-r", self.base_dir, "--html",
                                "--html-details"] + tracefiles +
                               ["-o", os.path.join(subdir, "index.html")],
                               stdout=coveragelog)
class HardwareMap:

    schema_path = os.path.join(ZEPHYR_BASE, "scripts", "sanity_chk", "hwmap-schema.yaml")

    manufacturer = [
        'ARM',
        'SEGGER',
        'MBED',
        'STMicroelectronics',
        'Atmel Corp.',
        'Texas Instruments',
        'Silicon Labs',
        'NXP Semiconductors',
        'Microchip Technology Inc.',
        'FTDI',
        'Digilent'
    ]

    runner_mapping = {
        'pyocd': [
            'DAPLink CMSIS-DAP',
            'MBED CMSIS-DAP'
        ],
        'jlink': [
            'J-Link',
            'J-Link OB'
        ],
        'openocd': [
            'STM32 STLink', '^XDS110.*', 'STLINK-V3'
        ],
        'dediprog': [
            'TTL232R-3V3',
            'MCP2200 USB Serial Port Emulator'
        ]
    }

    def __init__(self):
        self.detected = []
        self.connected_hardware = []

    def load_device_from_cmdline(self, serial, platform, is_pty):
        device = {
            "serial": None,
            "platform": platform,
            "serial_pty": None,
            "counter": 0,
            "available": True,
            "connected": True
        }

        if is_pty:
            device['serial_pty'] = serial
        else:
            device['serial'] = serial

        self.connected_hardware.append(device)

    def load_hardware_map(self, map_file):
        hwm_schema = scl.yaml_load(self.schema_path)
        self.connected_hardware = scl.yaml_load_verify(map_file, hwm_schema)
        for i in self.connected_hardware:
            i['counter'] = 0

    def scan_hw(self, persistent=False):
        from serial.tools import list_ports

        if persistent and platform.system() == 'Linux':
            # On Linux, /dev/serial/by-id provides symlinks to
            # '/dev/ttyACMx' nodes using names which are unique as
            # long as manufacturers fill out USB metadata nicely.
            #
            # This creates a map from '/dev/ttyACMx' device nodes
            # to '/dev/serial/by-id/usb-...' symlinks. The symlinks
            # go into the hardware map because they stay the same
            # even when the user unplugs / replugs the device.
            #
            # Some inexpensive USB/serial adapters don't result
            # in unique names here, though, so use of this feature
            # requires explicitly setting persistent=True.
            by_id = Path('/dev/serial/by-id')
            def readlink(link):
                return str((by_id / link).resolve())

            persistent_map = {readlink(link): str(link)
                              for link in by_id.iterdir()}
        else:
            persistent_map = {}

        serial_devices = list_ports.comports()
        logger.info("Scanning connected hardware...")
        for d in serial_devices:
            if d.manufacturer in self.manufacturer:

                # TI XDS110 can have multiple serial devices for a single board
                # assume endpoint 0 is the serial, skip all others
                if d.manufacturer == 'Texas Instruments' and not d.location.endswith('0'):
                    continue
                s_dev = {}
                s_dev['platform'] = "unknown"
                s_dev['id'] = d.serial_number
                s_dev['serial'] = persistent_map.get(d.device, d.device)
                s_dev['product'] = d.product
                s_dev['runner'] = 'unknown'
                for runner, _ in self.runner_mapping.items():
                    products = self.runner_mapping.get(runner)
                    if d.product in products:
                        s_dev['runner'] = runner
                        continue
                    # Try regex matching
                    for p in products:
                        if re.match(p, d.product):
                            s_dev['runner'] = runner

                s_dev['available'] = True
                s_dev['connected'] = True
                self.detected.append(s_dev)
            else:
                logger.warning("Unsupported device (%s): %s" % (d.manufacturer, d))

    def write_map(self, hwm_file):
        # use existing map
        if os.path.exists(hwm_file):
            with open(hwm_file, 'r') as yaml_file:
                hwm = yaml.load(yaml_file, Loader=SafeLoader)
                hwm.sort(key=lambda x: x['serial'] or '')

                # disconnect everything
                for h in hwm:
                    h['connected'] = False
                    h['serial'] = None

                self.detected.sort(key=lambda x: x['serial'] or '')
                for d in self.detected:
                    for h in hwm:
                        if d['id'] == h['id'] and d['product'] == h['product'] and not h['connected'] and not d.get('match', False):
                            h['connected'] = True
                            h['serial'] = d['serial']
                            d['match'] = True

                new = list(filter(lambda n: not n.get('match', False), self.detected))
                hwm = hwm + new

                logger.info("Registered devices:")
                self.dump(hwm)

            with open(hwm_file, 'w') as yaml_file:
                yaml.dump(hwm, yaml_file, Dumper=Dumper, default_flow_style=False)

        else:
            # create new file
            with open(hwm_file, 'w') as yaml_file:
                yaml.dump(self.detected, yaml_file, Dumper=Dumper, default_flow_style=False)
            logger.info("Detected devices:")
            self.dump(self.detected)

    @staticmethod
    def dump(hwmap=[], filtered=[], header=[], connected_only=False):
        print("")
        table = []
        if not header:
            header = ["Platform", "ID", "Serial device"]
        for p in sorted(hwmap, key=lambda i: i['platform']):
            platform = p.get('platform')
            connected = p.get('connected', False)
            if filtered and platform not in filtered:
                continue

            if not connected_only or connected:
                table.append([platform, p.get('id', None), p.get('serial')])

        print(tabulate(table, headers=header, tablefmt="github"))


def size_report(sc):
    logger.info(sc.filename)
    logger.info("SECTION NAME             VMA        LMA     SIZE  HEX SZ TYPE")
    for i in range(len(sc.sections)):
        v = sc.sections[i]

        logger.info("%-17s 0x%08x 0x%08x %8d 0x%05x %-7s" %
                    (v["name"], v["virt_addr"], v["load_addr"], v["size"], v["size"],
                     v["type"]))

    logger.info("Totals: %d bytes (ROM), %d bytes (RAM)" %
                (sc.rom_size, sc.ram_size))
    logger.info("")



def export_tests(filename, tests):
    with open(filename, "wt") as csvfile:
        fieldnames = ['section', 'subsection', 'title', 'reference']
        cw = csv.DictWriter(csvfile, fieldnames, lineterminator=os.linesep)
        for test in tests:
            data = test.split(".")
            if len(data) > 1:
                subsec = " ".join(data[1].split("_")).title()
                rowdict = {
                    "section": data[0].capitalize(),
                    "subsection": subsec,
                    "title": test,
                    "reference": test
                }
                cw.writerow(rowdict)
            else:
                logger.info("{} can't be exported".format(test))
