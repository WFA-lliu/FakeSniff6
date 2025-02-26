#! python3
import os
import sys
import argparse
import logging
import re
import signal
import subprocess
from subprocess import CalledProcessError
import time
import datetime
from datetime import datetime
from telnetlib import Telnet

class Interceptor():
    IDLE_TMO: int = 30
    CLT_DELI: str = "\n"
    def __init__(self, service_ipv4: str = "127.0.0.1", service_port: int = 50505, actual_prog_dir: str = "", actual_prog_fn: str = "python3") -> None:
        self.service_ipv4 = service_ipv4
        self.service_port = service_port
        self.actual_prog_fn = actual_prog_fn
        self.actual_prog_dir = actual_prog_dir

    def entry(self) -> None:
        #check whether the fundamental utility is existing or not
        try:
            cmd: str = "socat -V"
            cmd_output = subprocess.check_output(cmd, shell=True)
            logging.debug("cmd_output = %s" % (repr(cmd_output)))
        except CalledProcessError as e:
            logging.error("Execution failed: %s" % (e))
            return
        pid: int = os.fork()
        if pid == 0:
            #child
            logging.debug("forked pid = %d; current pid = %d; i.e. child" % (pid, os.getpid()))
            #launch the fundamental utility
            try:
                cmd: str = None
                if os.path.isdir(self.actual_prog_dir):
                    cmd: str = "socat tcp-listen:%d,reuseaddr,range=%s/32 exec:\"%s\",path=%s" % (self.service_port, self.service_ipv4, self.actual_prog_fn, self.actual_prog_dir)
                else:
                    cmd: str = "socat tcp-listen:%d,reuseaddr,range=%s/32 exec:\"%s\"" % (self.service_port, self.service_ipv4, self.actual_prog_fn)
                cmd_output = subprocess.check_output(cmd, shell=True)
                logging.debug("cmd_output = %s" % (repr(cmd_output)))
            except CalledProcessError as e:
                logging.error("Execution failed: %s" % (e))
                return
        elif pid > 0:
            #parent
            logging.debug("forked pid = %d; current pid = %d; i.e. parent" % (pid, os.getpid()))
            #delay, wait for the server is ready to be connected
            time.sleep(1)
            #to connect the actual program via the fundamental utility
            force_term: bool = True
            try:
                CLT_TMO: int = 10
                clt = Telnet()
                clt.open(host = self.service_ipv4, port = self.service_port, timeout = CLT_TMO)
                clt_sock_laddr: tuple = clt.get_socket().getsockname()
                clt_sock_raddr: tuple = clt.get_socket().getpeername()
                logging.debug("local: ip = %s, port = %d; remote: ip = %s, port = %d" % (clt_sock_laddr[0], clt_sock_laddr[1], clt_sock_raddr[0], clt_sock_raddr[1]))
                dt_last: datetime = datetime.now()
                kept: bool = True
                while(kept is True):
                    dt_current: datetime = datetime.now()
                    rcv = clt.read_until(Interceptor.CLT_DELI.encode(), CLT_TMO)
                    logging.debug("len = %d; rcv = %s" % (len(rcv), rcv))
                    #dispatch message
                    rsp: str = rcv.decode("UTF-8").rstrip()
                    logging.debug("rsp = %s" % (repr(rsp)))
                    req: str = None
                    term: bool = False
                    (term, req) = self.dispatch(rsp)
                    logging.debug("term = %s, req = %s" % (repr(term), repr(req)))
                    if req is not None:
                        req += Interceptor.CLT_DELI
                        clt.write(bytes(req, "UTF-8"))
                    #idle detection
                    if dt_last is not None:
                        if len(rcv) == 0:
                            td: datetime = dt_current - dt_last
                            if Interceptor.IDLE_TMO < td.total_seconds():
                                kept = False
                    if len(rcv) > 0:
                        dt_last = dt_current
                clt.close()
            except ConnectionRefusedError as e:
                logging.error("Execution failed: %s" % (e))
            except EOFError as e:
                force_term = False
                logging.warn("Execution warning: %s" % (e))
            finally:
                if force_term is True:
                    os.kill(pid, signal.SIGTERM)
                    try:
                        cmd: str = "pidof socat && killall socat"
                        cmd_output = subprocess.check_output(cmd, shell=True)
                        logging.debug("cmd_output = %s" % (repr(cmd_output)))
                    except CalledProcessError as e:
                        logging.error("Execution failed: %s" % (e))
                        return
        else:
            pass

    def dispatch(self, rsp: str = None) -> tuple:
        logging.debug("len = %d; rsp = %s" % (len(rsp), repr(rsp)))
        req: str = None
        term: bool = False
        return (term, req)

class SampleTap(Interceptor):
    def __init__(self, service_ipv4: str = "127.0.0.1", service_port: int = 50505, actual_prog_dir: str = "auxiliary", actual_prog_fn: str = "sample argv1 argv2 argv3") -> None:
        return super().__init__(service_ipv4 = service_ipv4, service_port = service_port, actual_prog_dir = actual_prog_dir, actual_prog_fn = actual_prog_fn)

    def dispatch(self, rsp: str = None) -> tuple:
        logging.debug("len = %d; rsp = %s" % (len(rsp), repr(rsp)))
        req: str = None
        term: bool = False
        sample: list = ["hello", "world", "exit"]
        if re.search("onetime", rsp) is not None:
            logging.debug("initiated")
            self.cnt = 0
        elif re.search("interactive", rsp) is not None:
            logging.debug("incremental/stateful")
            self.cnt += 1
        elif re.search("exit", rsp) is not None:
            logging.debug("exit/leave")
            term = True
        else:
            logging.debug("omitted")
            pass
        if term is False and hasattr(self, "cnt") and self.cnt < len(sample):
            req = sample[self.cnt]
        return (term, req)

if __name__ == "__main__":
    my_parser = argparse.ArgumentParser(description="CLI argument parsing")
    my_parser.add_argument("-v",
        "--verbose",
        action="store_true",
        help="verbosity")
    args = my_parser.parse_args()
    if args.verbose == True :
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.ERROR)
    logging.debug("args: " + repr(args))

    st = SampleTap()
    st.entry()
    logging.info("complete; current pid = %d." % (os.getpid()))

#FakeSniff6 - by Leo Liu
