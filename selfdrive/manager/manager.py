#!/usr/bin/env python3
import datetime
import os
import signal
import subprocess
import sys
import traceback

import cereal.messaging as messaging
import selfdrive.crash as crash
from common.basedir import BASEDIR
from common.params import Params, ParamKeyType
from common.text_window import TextWindow
from selfdrive.boardd.set_time import set_time
from selfdrive.hardware import HARDWARE, PC
from selfdrive.manager.helpers import unblock_stdout
from selfdrive.manager.process import ensure_running
from selfdrive.manager.process_config import managed_processes
from selfdrive.athena.registration import register, UNREGISTERED_DONGLE_ID
from selfdrive.swaglog import cloudlog, add_file_handler
from selfdrive.version import dirty, get_git_commit, version, origin, branch, commit, \
                              terms_version, training_version, comma_remote, \
                              get_git_branch, get_git_remote

sys.path.append(os.path.join(BASEDIR, "pyextra"))

def manager_init():

  # update system time from panda
  set_time(cloudlog)

  params = Params()
  params.clear_all(ParamKeyType.CLEAR_ON_MANAGER_START)

  default_params = [
    ("CompletedTrainingVersion", "0"),
    ("HasAcceptedTerms", "0"),
    ("OpenpilotEnabledToggle", "1"),

    ("IsOpenpilotViewEnabled", "0"),
    ("OpkrAutoResume", "0"),
    ("OpkrLiveSteerRatio", "0"),
    ("OpkrTurnSteeringDisable", "0"),
    ("PutPrebuiltOn", "0"),
    # {"OpkrUIBrightnessOff", "10" },
    ("OpkrAutoScreenOff", "0"),
    ("OpkrAutoFocus", "0"),
    ("OpkrUIBrightness", "0"),
    ("OpkrUIVolumeBoost", "0"),    
    ("LongitudinalControl", "0"),
    ("OpkrRunNaviOnBoot", "0"),
    ("OpkrSSHLegacy", "0"), 
  ]
  if not PC:
    default_params.append(("LastUpdateTime", datetime.datetime.utcnow().isoformat().encode('utf8')))

  if params.get_bool("RecordFrontLock"):
    params.put_bool("RecordFront", True)

  if not params.get_bool("DisableRadar_Allow"):
    params.delete("DisableRadar")

  # set unset params
  for k, v in default_params:
    if params.get(k) is None:
      params.put(k, v)

  # is this dashcam?
  if os.getenv("PASSIVE") is not None:
    params.put_bool("Passive", bool(int(os.getenv("PASSIVE"))))

  if params.get("Passive") is None:
    raise Exception("Passive must be set to continue")

  # Create folders needed for msgq
  try:
    os.mkdir("/dev/shm")
  except FileExistsError:
    pass
  except PermissionError:
    print("WARNING: failed to make /dev/shm")

  # set version params
  params.put("Version", version)
  params.put("TermsVersion", terms_version)
  params.put("TrainingVersion", training_version)
  params.put("GitCommit", get_git_commit(default=""))
  params.put("GitBranch", get_git_branch(default=""))
  params.put("GitRemote", get_git_remote(default=""))

  # set dongle id
  reg_res = register(show_spinner=True)
  if reg_res:
    dongle_id = reg_res
  else:
    serial = params.get("HardwareSerial")
    raise Exception(f"Registration failed for device {serial}")
  os.environ['DONGLE_ID'] = dongle_id  # Needed for swaglog

  if not dirty:
    os.environ['CLEAN'] = '1'

  cloudlog.bind_global(dongle_id=dongle_id, version=version, dirty=dirty,
                       device=HARDWARE.get_device_type())

  if comma_remote and not (os.getenv("NOLOG") or os.getenv("NOCRASH") or PC):
    crash.init()
  crash.bind_user(id=dongle_id)
  crash.bind_extra(dirty=dirty, origin=origin, branch=branch, commit=commit,
                   device=HARDWARE.get_device_type())


def manager_prepare():
  for p in managed_processes.values():
    p.prepare()


def manager_cleanup():
  for p in managed_processes.values():
    p.stop()

  cloudlog.info("everything is dead")


def manager_thread():
  cloudlog.info("manager start")
  cloudlog.info({"environ": os.environ})


  ignore = []
  params = Params()
  enableLogger = params.get_bool("UploadRaw")
  if enableLogger:
    # save boot log
    subprocess.call("./bootlog", cwd=os.path.join(BASEDIR, "selfdrive/loggerd"))
  else:
    ignore += ["loggerd","logmessaged","deleter","tombstoned","uploader","updated"] #,"androidd"]
    # ignore += ["loggerd","logmessaged","deleter","tombstoned","uploader","updated","androidd"] #,"rtshield"]
    # ignore += ["manage_athenad","proclogd","clocksd","timezoned"]


  if params.get("DongleId", encoding='utf8') == UNREGISTERED_DONGLE_ID:
    ignore += ["manage_athenad", "uploader"]
  if os.getenv("NOBOARD") is not None:
    ignore.append("pandad")
  if os.getenv("BLOCK") is not None:
    ignore += os.getenv("BLOCK").split(",")

  ensure_running(managed_processes.values(), started=False, not_run=ignore)

  started_prev = False
  sm = messaging.SubMaster(['deviceState'])
  pm = messaging.PubMaster(['managerState'])

  while True:
    sm.update()
    not_run = ignore[:]

    if sm['deviceState'].freeSpacePercent < 5:
      not_run.append("loggerd")

    started = sm['deviceState'].started
    driverview = params.get_bool("IsDriverViewEnabled")
    ensure_running(managed_processes.values(), started, driverview, not_run)

    # trigger an update after going offroad
    if started_prev and not started and 'updated' in managed_processes:
      os.sync()
      managed_processes['updated'].signal(signal.SIGHUP)

    started_prev = started

    running_list = ["%s%s\u001b[0m" % ("\u001b[32m" if p.proc.is_alive() else "\u001b[31m", p.name)
                    for p in managed_processes.values() if p.proc]
    cloudlog.debug(' '.join(running_list))

    # send managerState
    msg = messaging.new_message('managerState')
    msg.managerState.processes = [p.get_process_state_msg() for p in managed_processes.values()]
    pm.send('managerState', msg)

    # Exit main loop when uninstall/shutdown/reboot is needed
    shutdown = False
    for param in ("DoUninstall", "DoShutdown", "DoReboot"):
      if params.get_bool(param):
        cloudlog.warning(f"Shutting down manager - {param} set")
        shutdown = True

    if shutdown:
      break

def map_exec():
  os.system("am start com.mnsoft.mappyobn/com.mnsoft.mappy.MainActivity &")  # map 실행.

def map_hide():
  os.system("am start --activity-task-on-home com.opkr.maphack/com.opkr.maphack.MainActivity")  # map backgrand로 전환합니다.

def map_return():
  os.system("am start --activity-task-on-home com.mnsoft.mappyobn/com.mnsoft.mappy.MainActivity")


def main():
  param_navi = Params().get("OpkrRunNaviOnBoot")
  if param_navi is not None:
    navi_on_boot = int(param_navi)
  else:
    navi_on_boot = 0

  if navi_on_boot:
    map_exec()

  prepare_only = os.getenv("PREPAREONLY") is not None

  manager_init()

  # Start UI early so prepare can happen in the background
  if not prepare_only:
    managed_processes['ui'].start()

  if navi_on_boot:
    map_hide()

  manager_prepare()

  if prepare_only:
    return

  # SystemExit on sigterm
  signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(1))

  try:
    manager_thread()
  except Exception:
    traceback.print_exc()
    crash.capture_exception()
  finally:
    manager_cleanup()

  params = Params()
  if params.get_bool("DoUninstall"):
    cloudlog.warning("uninstalling")
    HARDWARE.uninstall()
  elif params.get_bool("DoReboot"):
    cloudlog.warning("reboot")
    HARDWARE.reboot()
  elif params.get_bool("DoShutdown"):
    cloudlog.warning("shutdown")
    HARDWARE.shutdown()


if __name__ == "__main__":
  unblock_stdout()

  try:
    main()
  except Exception:
    add_file_handler(cloudlog)
    cloudlog.exception("Manager failed to start")

    # Show last 3 lines of traceback
    error = traceback.format_exc(-3)
    error = "Manager failed to start\n\n" + error
    with TextWindow(error) as t:
      t.wait_for_exit()

    raise

  # manual exit because we are forked
  sys.exit(0)
