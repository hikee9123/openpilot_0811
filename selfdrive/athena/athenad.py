#!/usr/bin/env python3
import base64
import hashlib
import io
import json
import os
import sys
import queue
import random
import select
import socket
import threading
import time
import jwt

from collections import namedtuple
from functools import partial
from typing import Any


from jsonrpc import JSONRPCResponseManager, dispatcher
from websocket import ABNF, WebSocketTimeoutException, WebSocketException, create_connection
from datetime import datetime, timedelta
import cereal.messaging as messaging
from cereal.services import service_list
from common.api import Api
from common.api import api_get
from common.basedir import PERSIST
from common.params import Params
from common.realtime import sec_since_boot
from selfdrive.hardware import HARDWARE, PC, TICI
from selfdrive.loggerd.config import ROOT
from selfdrive.loggerd.xattr_cache import getxattr, setxattr
from selfdrive.swaglog import cloudlog, SWAGLOG_DIR
from selfdrive.version import get_version, get_git_remote, get_git_branch, get_git_commit

ATHENA_HOST = os.getenv('ATHENA_HOST', 'wss://api.retropilot.org:4040')
HANDLER_THREADS = int(os.getenv('HANDLER_THREADS', "4"))
LOCAL_PORT_WHITELIST = set([8022])

LOG_ATTR_NAME = 'user.upload'
LOG_ATTR_VALUE_MAX_UNIX_TIME = int.to_bytes(2147483647, 4, sys.byteorder)
RECONNECT_TIMEOUT_S = 70

dispatcher["echo"] = lambda s: s
recv_queue: Any = queue.Queue()
send_queue: Any = queue.Queue()
upload_queue: Any = queue.Queue()
log_send_queue: Any = queue.Queue()
log_recv_queue: Any = queue.Queue()
cancelled_uploads: Any = set()
UploadItem = namedtuple('UploadItem', ['path', 'url', 'headers', 'created_at', 'id'])





# security: user should be able to request any message from their car
@dispatcher.add_method
def getMessage(service=None, timeout=1000):
  if service is None or service not in service_list:
    raise Exception("invalid service")

  socket = messaging.sub_sock(service, timeout=timeout)
  ret = messaging.recv_one(socket)

  if ret is None:
    raise TimeoutError

  return ret.to_dict()


@dispatcher.add_method
def getVersion():
  return {
    "version": get_version(),
    "remote": get_git_remote(),
    "branch": get_git_branch(),
    "commit": get_git_commit(),
  }




@dispatcher.add_method
def reboot():
  sock = messaging.sub_sock("deviceState", timeout=1000)
  ret = messaging.recv_one(sock)
  if ret is None or ret.deviceState.started:
    raise Exception("Reboot unavailable")

  def do_reboot():
    time.sleep(2)
    HARDWARE.reboot()

  threading.Thread(target=do_reboot).start()

  return {"success": 1}


@dispatcher.add_method
def getPublicKey():
  if not os.path.isfile(PERSIST + '/comma/id_rsa.pub'):
    return None

  with open(PERSIST + '/comma/id_rsa.pub', 'r') as f:
    return f.read()

@dispatcher.add_method
def getPrivateKey():
  if not os.path.isfile(PERSIST + '/comma/id_rsa'):
    return None  

  with open(PERSIST + '/comma/id_rsa', 'r') as f:
    return f.read()

@dispatcher.add_method
def getSshAuthorizedKeys():
  return Params().get("GithubSshKeys", encoding='utf8') or ''


@dispatcher.add_method
def getSimInfo():
  return HARDWARE.get_sim_info()


@dispatcher.add_method
def getNetworkType():
  return HARDWARE.get_network_type()




def get_logs_to_send_sorted():
  # TODO: scan once then use inotify to detect file creation/deletion
  curr_time = int(time.time())
  logs = []
  for log_entry in os.listdir(SWAGLOG_DIR):
    log_path = os.path.join(SWAGLOG_DIR, log_entry)
    try:
      time_sent = int.from_bytes(getxattr(log_path, LOG_ATTR_NAME), sys.byteorder)
    except (ValueError, TypeError):
      time_sent = 0
    # assume send failed and we lost the response if sent more than one hour ago
    if not time_sent or curr_time - time_sent > 3600:
      logs.append(log_entry)
  # return logs in order they should be sent
  # excluding most recent (active) log file
  return sorted(logs[:-1])


def log_handler(end_event):
  if PC:
    return

  log_files = []
  last_scan = 0
  while not end_event.is_set():
    try:
      curr_scan = sec_since_boot()
      if curr_scan - last_scan > 10:
        log_files = get_logs_to_send_sorted()
        last_scan = curr_scan

      # send one log
      curr_log = None
      if len(log_files) > 0:
        log_entry = log_files.pop()
        cloudlog.debug(f"athena.log_handler.forward_request {log_entry}")
        try:
          curr_time = int(time.time())
          log_path = os.path.join(SWAGLOG_DIR, log_entry)
          setxattr(log_path, LOG_ATTR_NAME, int.to_bytes(curr_time, 4, sys.byteorder))
          with open(log_path, "r") as f:
            jsonrpc = {
              "method": "forwardLogs",
              "params": {
                "logs": f.read()
              },
              "jsonrpc": "2.0",
              "id": log_entry
            }
            log_send_queue.put_nowait(json.dumps(jsonrpc))
            curr_log = log_entry
        except OSError:
          pass  # file could be deleted by log rotation

      # wait for response up to ~100 seconds
      # always read queue at least once to process any old responses that arrive
      for _ in range(100):
        if end_event.is_set():
          break
        try:
          log_resp = json.loads(log_recv_queue.get(timeout=1))
          log_entry = log_resp.get("id")
          log_success = "result" in log_resp and log_resp["result"].get("success")
          cloudlog.debug(f"athena.log_handler.forward_response {log_entry} {log_success}")
          if log_entry and log_success:
            log_path = os.path.join(SWAGLOG_DIR, log_entry)
            try:
              setxattr(log_path, LOG_ATTR_NAME, LOG_ATTR_VALUE_MAX_UNIX_TIME)
            except OSError:
              pass  # file could be deleted by log rotation
          if curr_log == log_entry:
            break
        except queue.Empty:
          if curr_log is None:
            break

    except Exception:
      cloudlog.exception("athena.log_handler.exception")




def backoff(retries):
  return random.randrange(0, min(128, int(2 ** retries)))



def main():
  params = Params()
  dongle_id = params.get("DongleId", encoding='utf-8')

  ws_uri = ATHENA_HOST + "/ws/v2/" + dongle_id
  api = Api(dongle_id)

  conn_retries = 0
  serial = HARDWARE.get_serial()
  public_key = getPublicKey()
  private_key = getPrivateKey()
  register_token = jwt.encode({'register': True, 'exp': datetime.utcnow() + timedelta(hours=1)}, private_key, algorithm='RS256')
  try:
    imei1, imei2 = HARDWARE.get_imei(0), HARDWARE.get_imei(1)
  except Exception:
    cloudlog.exception("Error getting imei, trying again...")
    time.sleep(1)

  while 1:
    try:
      #cloudlog.event("athenad.main.connecting_ws", ws_uri=ws_uri)

      #url_resp = api.get("v1.3/"+dongle_id+"/upload_url/", timeout=10, path="", access_token=api.get_token())
      resp = api_get("v2/pilotauth/", method='POST', timeout=15,
                       imei=imei1, imei2=imei2, serial=serial, public_key=public_key, register_token=register_token)

      
    
      if resp.status_code in (402, 403):
        params.delete("LastAthenaPingTime")
        cloudlog.info(f"Unable to register device, got {resp.status_code}")
        #dongle_id = UNREGISTERED_DONGLE_ID
      else:
        last_ping = int(sec_since_boot() * 1e9)
        Params().put("LastAthenaPingTime", str(last_ping))
        
        dongleauth = json.loads(resp.text)
        dongle_id = dongleauth["dongle_id"]
        print("athenad.py =>  resp.status_code={}  dongle_id={}".format( resp.status_code, dongle_id) ) 


      conn_retries = 2

    except (KeyboardInterrupt, SystemExit):
      cloudlog.exception("athenad.main.KeyboardInterrupt")
      break
    except (ConnectionError, TimeoutError, WebSocketException):
      cloudlog.exception("athenad.main.ConnectionError")
      conn_retries += 1
      params.delete("LastAthenaPingTime")
    except Exception:
      cloudlog.exception("athenad.main.exception")

      conn_retries += 1
      params.delete("LastAthenaPingTime")

    time.sleep(backoff(conn_retries))


if __name__ == "__main__":
  main()
