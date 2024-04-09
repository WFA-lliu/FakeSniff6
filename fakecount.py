#! python3
import os
import sys
import argparse
import logging
import re
import codecs
from fakesniff import FakeSniff

class FakeCount(FakeSniff):
    def __init__(self) -> None:
        super().__init__()
        #variables for pattern matching
        self.patt["deli_rsp"] = "<-{2,3}\s+"
        self.patt["abort"] = False
        self.patt["capi"] = dict()
        self.patt["capi"]["*"] = self.__invoke
        self.patt["capi_ret"] = self.__returned_check
        #variables for basic configuration
        self.cfg["telnet"] = False
        #variables for status (temporary) and statistics (finally)

    def reset(self) -> None:
        super().reset()

    def __invoke(self, argv: list) -> bool:
        logging.debug("INVOKE: " + argv[0])
        self.status["invoked"] = self.patt["deli_arg"].join(argv)
        self.status["returned"] = ""
        self.status["silenced"] = False
        return True

    def __returned_check(self, argv: list) -> bool:
        logging.debug("RETURNED CHECK: " + ((argv[1] + ".") if len(argv) >= 2 else (repr(argv) + "!")))
        #force last state as fine
        capi_req = self.status["invoked"].split(self.patt["deli_arg"])
        capi_rsp = self.status["returned"].split(self.patt["deli_arg"])
        verdict: str = "omitted"
        if self.status["silenced"] is False:
            argc = len(argv)
            if argv[0] == "status":
                if argv[1] == "COMPLETE":
                    if argc >= 4:
                        if argv[2].upper() in map(str.upper, ["CheckResult", "FilterStatus", "Msg", "Upload"]):
                            if argv[3].upper() in map(str.upper, ["Success"]):
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
            verdict = "omitted"
        if verdict == "consistent":
            logging.info("capi: " + capi_req[0] + ";" + "result: " + verdict)
        else:
            logging.info("invoked: " + self.status["invoked"] + ";")
            logging.debug("returned: " + self.status["returned"] + ";")
            logging.info("argv: " + self.patt["deli_arg"].join(argv) + ";")
            logging.info("result: " + verdict)
        self.status["verdict"][verdict] += 1
        return True

    @staticmethod
    def find_interpreting_handle(dir: str = ".", alias: str = None) -> tuple:
        fn: str = ""
        hdl: set = set()
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
                    with codecs.open(path, "r", encoding = "utf-8", errors = "ignore") as file:
                        for line in file:
                            VER_INFIX: str = "WiFiTestSuite Version"
                            ret_patt_ver_search = re.search(VER_INFIX, line)
                            if ret_patt_ver_search is not None:
                                found = True
                                fn = item
                                break
                    if found is True:
                        with codecs.open(path, "r", encoding = "utf-8", errors = "ignore") as file:
                            for line in file:
                                CAPI_INFIX: str = "_get_info"
                                ret_patt_capi_search = re.search(CAPI_INFIX, line)
                                if ret_patt_capi_search is not None:
                                    hdl_end = line.find(")")
                                    hdl_begin = line.find("(")
                                    al_end = hdl_begin - 1
                                    al_begin = line.rfind(" ", 0, al_end)
                                    al = line[al_begin+1:al_end]
                                    logging.debug("al: " + al)
                                    if alias is None:
                                        hdl.add(line[hdl_begin+1:hdl_end])
                                    else:
                                        if al == alias:
                                            hdl.add(line[hdl_begin+1:hdl_end])
                                            break
                                        else:
                                            pass
                    if found is True:
                        break
                    fn = ""
        return (hdl, fn)

    def interpret(self, dir: str = "", fn: str = "", suff: str = "", handle: str = "127.0.0.1:9999", handle_restore: str = None, handle_invoke: str = None, uldir: str = None) -> tuple:
        path = dir
        if not path.endswith(os.path.sep):
            path += os.path.sep
        path += fn
        logging.debug("PATH: " + path)
        self.cfg["dir"] = dir
        self.cfg["fn"] = fn
        self.cfg["suff"] = suff
        self.patt["handle"] = handle

        ret: bool = True
        if ret is True:
            with codecs.open(path, "r", encoding = "utf-8", errors = "ignore") as file:
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
        return (ret, self.status["verdict"])

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
    my_parser.add_argument("-n",
        "--name",
        metavar="name",
        default=None,
        type=str,
        help="display name for specific handle")
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

    args = my_parser.parse_args()

    if(args.verbose == True):
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.ERROR)
    logging.debug("args: " + repr(args))

    ret = True
    if args.auto is True:
        fldr = FakeCount.find_interpreting_directory(args.directory)
        fc = FakeCount()
        for f in fldr:
            (hdl, filename) = FakeCount.find_interpreting_handle(f, args.name)
            print("hdl: " + repr(hdl))
            print("filename: " + repr(filename))
            for h in hdl:
                (ret, stat) = fc.interpret(dir = f, fn = filename, suff = args.suffix, handle = h, handle_restore = None, handle_invoke = None, uldir = None)
                print("dir: \"%s\"; fn: \"%s\"; suffix: \"%s\"; state: %s; statistics: %s" % (f, filename, args.suffix, "true" if ret is True else "false", repr(stat)), flush=True)
            fc.reset()
    else:
        fc = FakeCount()
        (ret, stat) = fc.interpret(dir = args.directory, fn = args.filename, suff = args.suffix, handle = args.interpreted, handle_restore = None, handle_invoke = None, uldir = None)
        print("dir: \"%s\"; fn: \"%s\"; suffix: \"%s\"; state: %s; statistics: %s" % (args.directory, args.filename, args.suffix, "true" if ret is True else "false", repr(stat)), flush=True)

    sys.exit(0 if ret is True else 255)

#FakeSniff6 - by Leo Liu
