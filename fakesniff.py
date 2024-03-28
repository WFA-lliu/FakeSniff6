#! python3
import os
import sys
import argparse
import logging
import re
import tarfile
import gzip
import shutil
from ptftplib.tftpclient import TFTPClient
from ptftplib import proto
from ptftplib import notify
from telnetlib import Telnet

class FakeSniff():
    def __init__(self) -> None:
        #variables for pattern matching
        self.patt = dict()
        self.patt["deli_req"] = "--->"
        self.patt["deli_rsp"] = "<--\s+"
        self.patt["deli_arg"] = ","
        self.patt["deli_lf"] = False
        self.patt["deli_et"] = ""
        self.patt["api_idx"] = int(0)
        self.patt["ret_idx"] = int(1)
        self.patt["abort"] = True
        self.patt["capi"] = dict()
        self.patt["capi"]["*"] = self.__invoke
        self.patt["capi"]["sniffer_control_start"] = self.__restore
        self.patt["capi"]["sniffer_decrypt_trace"] = self.__invoke_ul
        self.patt["capi"]["sniffer_control_stop"] = self.__silence
        self.patt["capi"]["sniffer_control_upload"] = self.__silence
        self.patt["capi"]["sniffer_get_info"] = self.__silence
        self.patt["capi_ret"] = self.__returned_check
        #variables for basic configuration
        self.cfg = dict()
        self.cfg["tmpdir"] = "tmp"
        self.cfg["uldir"] = None
        self.cfg["dec_idx"] = int(0)
        self.cfg["reuse"] = True
        self.cfg["telnet"] = True
        self.cfg["tmo_running"] = int(5)
        self.cfg["tmo_result"] = int(45)
        self.cfg["tmo_exhaustive"] = int(5)
        self.cfg["dispose"] = False
        self.cfg["object_restore"] = None
        self.cfg["object_invoke"] = None
        #variables for status (temporary) and statistics (finally)
        self.status = dict()
        self.reset()

    def reset(self) -> None:
        self.status["silenced"] = True
        self.status["invoked"] = ""
        self.status["returned"] = "status" + self.patt["deli_arg"] + "COMPLETE"
        self.status["verdict"] = dict()
        self.status["verdict"]["consistent"] = int(0)
        self.status["verdict"]["inconsistent"] = int(0)
        self.status["verdict"]["malformed"] = int(0)
        self.status["verdict"]["omitted"] = int(0)

    def __silence(self, argv: list) -> bool:
        logging.debug("SILENCE: " + argv[0])
        #force last state as fine
        self.status["invoked"] = argv[0]
        self.status["returned"] = "status" + self.patt["deli_arg"] + "COMPLETE"
        self.status["silenced"] = True
        return True

    def __restore(self, argv: list) -> bool:
        logging.debug("RESTORE: " + argv[0])
        #last state depends on the SCP result
        ret: bool = False
        fn_param_key = "filename"
        fn_param_idx = [item.lower() for item in argv].index(fn_param_key.lower())
        #compressed file is expected
        fn = argv[fn_param_idx + 1]
        path = self.cfg["dir"]
        if not path.endswith(os.path.sep):
            path += os.path.sep
        path += fn
        path += self.cfg["suff"]
        logging.debug("path: " + path)
        path_rmt = None
        path_lcl = None
        if os.path.isfile(path):
            avail: bool = False
            if self.cfg["suff"] == ".pcapng.gz":
                path_lcl = self.cfg["tmpdir"] + os.path.sep + fn
                with gzip.open(path, "rb") as fnc:
                    with open(path_lcl, "wb") as fnct:
                        shutil.copyfileobj(fnc, fnct)
                path_rmt = fn
                avail = True
            elif self.cfg["suff"] == ".tar.gz":
                fnc = tarfile.open(path)
                if len(fnc.getnames()) > 0:
                    fnc.extractall(self.cfg["tmpdir"])
                    path_lcl = self.cfg["tmpdir"] + os.path.sep + fnc.getnames()[self.cfg["dec_idx"]]
                    path_rmt = os.path.basename(fnc.getnames()[self.cfg["dec_idx"]])
                fnc.close()
                avail = True
            else:
                pass
            if avail is True:
                logging.debug("path_rmt: " + path_rmt)
                logging.debug("path_lcl: " + path_lcl)
                if os.path.isfile(path_lcl):
                    #ready to put file by TFTP client
                    cwd = os.getcwd()
                    nwd = os.path.dirname(path_lcl)
                    os.chdir(nwd)
                    try:
                        if self.cfg["object_restore"] is None:
                            hdl = (self.cfg["handle_restore"].split(":")[0], int(self.cfg["handle_restore"].split(":")[1]))
                            exts = {proto.TFTP_OPTION_WINDOWSIZE: int(1), proto.TFTP_OPTION_BLKSIZE: int(1024)}
                            self.cfg["object_restore"] = TFTPClient(peer = hdl, opts = exts, mode = "octet", rfc1350 = False)
                            self.cfg["object_restore"].connect()
                            l = notify.getLogger('tftp-proto')
                            #l.setLevel(logging.root.level)
                            l.setLevel(logging.ERROR)
                        else:
                            pass
                        args = [os.path.basename(path_lcl)]
                        ret = self.cfg["object_restore"].put(args)
                    except Exception as e:
                        logging.exception(e)
                    finally:
                        if self.cfg["reuse"] is False:
                            self.cfg["object_restore"].finish()
                            self.cfg["object_restore"] = None
                    os.chdir(cwd)
                    logging.debug("cwd: " + os.getcwd())
                    self.status["invoked"] = argv[0]
                    self.status["returned"] = "status" + self.patt["deli_arg"] + "COMPLETE"
                    self.status["silenced"] = False
                else:
                    ret = False
            if ret is False:
                logging.error("RESTORE: " + fn)
                if self.patt["abort"] is False:
                    ret = True
                else:
                    pass
        else:
            pass
        return ret

    def __invoke_ul(self, argv: list) -> bool:
        logging.debug("INVOKE_UL: " + argv[0])
        dir_param_key = "destpath"
        dir: str = None
        try:
            dir_param_idx = [item.lower() for item in argv].index(dir_param_key.lower())
            dir = argv[dir_param_idx + 1]
        except ValueError:
            pass
        if dir is not None and self.cfg["uldir"] is not None and os.path.isdir(self.cfg["uldir"]):
            path = self.cfg["uldir"]
            if not path.endswith(os.path.sep):
                path += os.path.sep
            path += os.path.basename(dir)
            os.makedirs(path, mode = 0o777, exist_ok = True)
            argv[dir_param_idx + 1] = path
        return self.__invoke(argv)

    def __invoke(self, argv: list) -> bool:
        logging.debug("INVOKE: " + argv[0])
        #last state depends on the CAPI invocation result
        invoke_running_tmo: int = self.cfg["tmo_running"]
        invoke_result_tmo: int = self.cfg["tmo_result"]
        tmo_exhaustive: int = self.cfg["tmo_exhaustive"]
        argv_shown: int = 3
        capi: str = None
        ret: bool = False
        if self.cfg["telnet"] is True:
            try:
                if self.cfg["object_invoke"] is None:
                    self.cfg["object_invoke"] = Telnet()
                    self.cfg["object_invoke"].open(host = self.cfg["handle_invoke"].split(":")[0], port = int(self.cfg["handle_invoke"].split(":")[1]))
                capi = self.patt["deli_arg"].join(argv) + ("" if self.patt["deli_et"] is None else self.patt["deli_et"]) + ("\r\n" if self.patt["deli_lf"] is False else "\n")
                self.cfg["object_invoke"].write(bytes(capi, "UTF-8"))
                rcv = self.cfg["object_invoke"].read_until((b"\r\n" if self.patt["deli_lf"] is False else b"\n"), invoke_running_tmo)
                if len(rcv) == 0:
                    raise Exception("Empty (synchronous)")
                rsp = rcv.decode("UTF-8").rstrip().split(self.patt["deli_arg"])
                logging.debug("rsp (synchronous): " + str(rsp))
                if (rsp[0] == "status") and ("RUNNING" in rsp[1]):
                    #status running shall be hidden
                    rcv = self.cfg["object_invoke"].read_until((b"\r\n" if self.patt["deli_lf"] is False else b"\n"), invoke_result_tmo)
                    if len(rcv) == 0:
                        raise Exception("Empty (asynchronous)")
                    rsp = rcv.decode("UTF-8").rstrip().split(self.patt["deli_arg"])
                    logging.debug("rsp (asynchronous): " + str(rsp))
                if len(rsp) >= 2:
                    self.status["invoked"] = self.patt["deli_arg"].join(argv[:argv_shown])
                    self.status["returned"] = rcv.decode("UTF-8").rstrip()
                    self.status["silenced"] = False
                    ret = True
                if tmo_exhaustive > 0:
                    rcv = self.cfg["object_invoke"].read_until((b"\r\n" if self.patt["deli_lf"] is False else b"\n"), tmo_exhaustive)
                    if len(rcv) == 0:
                        logging.debug("rsp (extra): " + "empty")
                    else:
                        rsp = rcv.decode("UTF-8").rstrip().split(self.patt["deli_arg"])
                        logging.debug("rsp (extra): " + str(rsp))
                ret = True
            except Exception as e:
                pass
                #logging.exception(e)
            finally:
                if self.cfg["reuse"] is False:
                    self.cfg["object_invoke"].close()
                    self.cfg["object_invoke"] = None
        else:
            pass
        if ret is False:
            self.status["invoked"] = self.patt["deli_arg"].join(argv[:argv_shown])
            self.status["returned"] = "\"\""
            self.status["silenced"] = False
            if self.patt["abort"] is False:
                ret = True
            else:
                pass
        return ret

    def __returned_check(self, argv: list) -> bool:
        logging.debug("RETURNED CHECK: " + argv[1])
        #force last state as fine
        capi_req = self.status["invoked"].split(self.patt["deli_arg"])
        capi_rsp = self.status["returned"].split(self.patt["deli_arg"])
        verdict: str = "omitted"
        if self.status["silenced"] is False:
            argc = len(argv)
            if argc == len(capi_rsp):
                if argv[0] == capi_rsp[0]:
                    if argv[1] == capi_rsp[1]:
                        if argc >= 4:
                            if argv[2] == capi_rsp[2]:
                                if argv[3] == capi_rsp[3]:
                                    verdict = "consistent"
                                else:
                                    verdict = "inconsistent"
                            else:
                                verdict = "malformed"
                        else:
                            if argc == 2:
                                verdict = "consistent"
                            else:
                                verdict = "malformed"
                    else:
                        verdict = "inconsistent"
                else:
                    verdict = "malformed"
            else:
                verdict = "malformed"
        else:
            verdict = "omitted"
        if verdict == "consistent":
            logging.info("capi: " + capi_req[0] + ";" + "result: " + verdict)
        else:
            logging.info("invoked: " + self.status["invoked"] + ";")
            logging.info("returned: " + self.status["returned"] + ";")
            logging.info("argv: " + self.patt["deli_arg"].join(argv) + ";")
            logging.info("result: " + verdict)
        self.status["verdict"][verdict] += 1
        return True

    def interpret(self, dir: str = "", fn: str = "", suff: str = "", handle: str = "127.0.0.1:9999", handle_restore: str = "127.0.0.1:69", handle_invoke: str = "127.0.0.1:9999", uldir: str = None) -> tuple:
        path = dir
        if not path.endswith(os.path.sep):
            path += os.path.sep
        path += fn
        logging.debug("PATH: " + path)
        self.cfg["dir"] = dir
        self.cfg["fn"] = fn
        self.cfg["suff"] = suff
        self.patt["handle"] = handle
        self.cfg["handle_restore"] = handle_restore
        self.cfg["handle_invoke"] = handle_invoke
        self.cfg["uldir"] = uldir
        os.makedirs(self.cfg["tmpdir"], mode = 0o777, exist_ok = True)
        ret: bool = True
        if FakeSniff.is_valid_ip(self.patt["handle"].split(":")[0]) is False:
            ret = False
        elif FakeSniff.is_valid_ip(self.cfg["handle_restore"].split(":")[0]) is False:
            ret = False
        elif FakeSniff.is_valid_ip(self.cfg["handle_invoke"].split(":")[0]) is False:
            ret = False
        else:
            pass
        if ret is True:
            with open(path) as file:
                patt_req_search = self.patt["handle"] + ".*" + self.patt["deli_req"]
                patt_rsp_search = self.patt["handle"] + ".*" + self.patt["deli_rsp"]
                logging.debug("patt_req_search: " + patt_req_search)
                logging.debug("patt_rsp_search: " + patt_rsp_search)
                for line in file:
                    ret_patt_req_search = re.search(patt_req_search, line)
                    ret_patt_rsp_search = re.search(patt_rsp_search, line)
                    if ret_patt_req_search is not None:
                        capi_req = line[ret_patt_req_search.end()+1:].rstrip().split(self.patt["deli_arg"])
                        capi = capi_req[self.patt["api_idx"]].strip()
                        if capi in self.patt["capi"]:
                            #callback specific/hit
                            ret = self.patt["capi"][capi](capi_req[0::])
                        else:
                            #callback wildcard/fall-through
                            ret = self.patt["capi"]["*"](capi_req[0::])
                        if ret is False:
                            logging.error("REQ: " + capi_req[self.patt["api_idx"]].strip())
                            if self.patt["abort"] is False:
                                ret = True
                            else:
                                break
                    elif ret_patt_rsp_search is not None:
                        capi_rsp = line[ret_patt_rsp_search.end()+0:].lstrip().rstrip().split(self.patt["deli_arg"])
                        #callback
                        ret = self.patt["capi_ret"](capi_rsp)
                        if ret is False:
                            logging.error("RSP: " + capi_rsp[self.patt["ret_idx"]].strip())
                            if self.patt["abort"] is False:
                                ret = True
                            else:
                                break
                    else:
                        pass
        if self.cfg["object_restore"] is not None:
            self.cfg["object_restore"].finish()
            self.cfg["object_restore"] = None
        if self.cfg["object_invoke"] is not None:
            self.cfg["object_invoke"].close()
            self.cfg["object_invoke"] = None
        if self.cfg["dispose"] is True:
            try:
                shutil.rmtree(self.cfg["tmpdir"])
            except Exception as e:
                logging.exception(e)
        return (ret, self.status["verdict"])

    @staticmethod
    def find_interpreting_handle(dir: str = ".") -> tuple:
        fn: str = ""
        hdl: str = ""
        found: bool = False
        LOG_SUFFIX: str = ".log"
        items = os.listdir(dir)
        for item in items:
            path: str = dir
            if not path.endswith(os.path.sep):
                path += os.path.sep
            path += item
            logging.debug("path: " + path)
            if os.path.isfile(path):
                if path.endswith(LOG_SUFFIX):
                    with open(path) as file:
                        for line in file:
                            VER_INFIX: str = "WiFiTestSuite Version"
                            ret_patt_ver_search = re.search(VER_INFIX, line)
                            if ret_patt_ver_search is not None:
                                found = True
                                fn = item
                                break
                    if found is True:
                        with open(path) as file:
                            for line in file:
                                CAPI_INFIX: str = "sniffer_get_info"
                                ret_patt_capi_search = re.search(CAPI_INFIX, line)
                                if ret_patt_capi_search is not None:
                                    hdl_end = line.find(")")
                                    hdl_begin = line.find("(")
                                    hdl = line[hdl_begin+1:hdl_end]
                                    break
                    if found is True:
                        break
                    fn = ""
        return (hdl, fn)

    @staticmethod
    def find_interpreting_directory(dir: str = ".") -> list:
        folder = list()
        found: bool = False
        items = os.listdir(dir)
        for item in items:
            path: str = dir
            if not path.endswith(os.path.sep):
                path += os.path.sep
            path += item
            logging.debug("path: " + path)
            if os.path.isdir(path):
                folder.append(path)
        return folder

    @staticmethod
    def is_valid_ip(ip) -> bool:
        m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
        return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))


if __name__ == "__main__":
    my_parser = argparse.ArgumentParser(description="CLI argument parsing")
    my_parser.add_argument("-v",
        "--verbose",
        action="store_true",
        help="verbosity")
    my_parser.add_argument("-a",
        "--auto",
        action="store_true",
        help="auto-mode")
    my_parser.add_argument("-d",
        "--directory",
        metavar="directory",
        default="",
        type=str,
        help="directory of UCC log and capture")
    my_parser.add_argument("-f",
        "--filename",
        metavar="filename",
        default="",
        type=str,
        help="filename of UCC log")
    my_parser.add_argument("-s",
        "--suffix",
        metavar="suffix",
        default=".pcapng.gz",
        choices=[".pcapng.gz", ".tar.gz"],
        type=str,
        help="suffix of capture")
    my_parser.add_argument("-i",
        "--interpreted",
        metavar="interpreted",
        default="192.168.250.6:9999",
        type=str,
        help="interpreted handle")
    my_parser.add_argument("-o",
        "--oriented",
        metavar="oriented",
        default="",
        type=str,
        help="oriented IP")
    my_parser.add_argument("-r",
        "--report",
        metavar="report",
        default="fakesniff6-report.txt",
        type=str,
        help="filename of report after interpreted under auto-mode")
    my_parser.add_argument("-u",
        "--uploading",
        metavar="uploading",
        default=None,
        type=str,
        help="directory for uploading")

    args = my_parser.parse_args()

    if(args.verbose == True):
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.ERROR)
    logging.debug("args: " + repr(args))

    ret = True
    if args.auto is True:
        rpt = open(args.report, "w")
        fldr = FakeSniff.find_interpreting_directory(args.directory)
        fs = FakeSniff()
        for f in fldr:
            (hdl, filename) = FakeSniff.find_interpreting_handle(f)
            handle_restore = None
            handle_invoke = None
            if len(hdl.split(":")) >= 2:
                handle_restore = args.oriented + ":" + str(69)
                handle_invoke = args.oriented + ":" + hdl.split(":")[1]
            (ret, stat) = fs.interpret(dir = f, fn = filename, suff = args.suffix, handle = hdl, handle_restore = handle_restore, handle_invoke = handle_invoke, uldir = args.uploading)
            print("dir: \"%s\"; fn: \"%s\"; suffix: \"%s\"; state: %s; statistics: %s" % (f, filename, args.suffix, "true" if ret is True else "false", repr(stat)), file = rpt)
            print("dir: \"%s\"; fn: \"%s\"; suffix: \"%s\"; state: %s; statistics: %s" % (f, filename, args.suffix, "true" if ret is True else "false", repr(stat)))
            fs.reset()
        rpt.close()
    else:
        handle_restore = None
        handle_invoke = None
        if len(args.interpreted.split(":")) >= 2:
            handle_restore = args.oriented + ":" + str(69)
            handle_invoke = args.oriented + ":" + args.interpreted.split(":")[1]
        fs = FakeSniff()
        (ret, stat) = fs.interpret(dir = args.directory, fn = args.filename, suff = args.suffix, handle = args.interpreted, handle_restore = handle_restore, handle_invoke = handle_invoke, uldir = args.uploading)
        print("state: " + repr(ret) + ";" + "statistics: " + repr(stat))

    sys.exit(0 if ret is True else 255)

#FakeSniff6 - by Leo Liu
