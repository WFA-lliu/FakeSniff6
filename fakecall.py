#! python3
import os
import sys
import argparse
import logging
import re
from fakesniff import FakeSniff 

class FakeCall(FakeSniff):
    def __init__(self) -> None:
        super().__init__()
        #variables for pattern matching
        self.patt["abort"] = True
        self.patt["capi"]["traffic_agent_reset"] = self.__silence
        self.patt["capi"]["traffic_agent_config"] = self.__silence
        self.patt["capi"]["traffic_agent_receive_start"] = self.__silence
        self.patt["capi"]["traffic_agent_receive_stop"] = self.__silence
        self.patt["capi"]["traffic_agent_send"] = self.__silence
        self.patt["capi"]["traffic_send_ping"] = self.__silence
        self.patt["capi"]["traffic_stop_ping"] = self.__silence
        self.patt["capi_ret"] = self.__returned_check
        #variables for basic configuration
        self.cfg["telnet"] = True
        self.cfg["tmo_result"] = int(300)
        #variables for status (temporary) and statistics (finally)
        logging.debug("patt: " + repr(self.patt))
        logging.debug("cfg: " + repr(self.cfg))
        logging.debug("status: " + repr(self.status))

    def __silence(self, argv: list) -> bool:
        #TODO: to be refactored
        return self._FakeSniff__silence(argv)

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
                            elif argc == 3:
                                if argv[2] == capi_rsp[2]:
                                    verdict = "consistent"
                                else:
                                    verdict = "inconsistent"
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
                                CAPI_INFIX: str = "device_get_info"
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
    my_parser.add_argument("-i",
        "--interpreted",
        metavar="interpreted",
        default=None,
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

    args = my_parser.parse_args()

    if(args.verbose == True):
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.ERROR)
    logging.debug("args: " + repr(args))

    ret = True
    if args.auto is True:
        logging.info("name: " + args.name)
        rpt = open(args.report, "w")
        fldr = FakeSniff.find_interpreting_directory(args.directory)
        fc = FakeCall()
        for f in fldr:
            (hdl, filename) = FakeCall.find_interpreting_handle(f, args.name)
            for h in hdl:
                handle_invoke = None
                if len(h.split(":")) >= 2:
                    if len(args.oriented.split(":")) >= 2:
                        handle_invoke = args.oriented
                    else:
                        handle_invoke = args.oriented + ":" + h.split(":")[1]
                logging.info("filename: " + filename)
                logging.info("h: " + h)
                (ret, stat) = fc.interpret(dir = f, fn = filename, handle = h, handle_invoke = handle_invoke)
                print("dir: \"%s\"; fn: \"%s\"; state: %s; statistics: %s" % (f, filename, "true" if ret is True else "false", repr(stat)), file = rpt)
                print("dir: \"%s\"; fn: \"%s\"; state: %s; statistics: %s" % (f, filename, "true" if ret is True else "false", repr(stat)))
            fc.reset()
        rpt.close()
    else:
        handle_invoke = None
        if len(args.interpreted.split(":")) >= 2:
            if len(args.oriented.split(":")) >= 2:
                handle_invoke = args.oriented
            else:
                handle_invoke = args.oriented + ":" + args.interpreted.split(":")[1]
        fc = FakeCall()
        (ret, stat) = fc.interpret(dir = args.directory, fn = args.filename, handle = args.interpreted, handle_invoke = handle_invoke)
        print("state: " + repr(ret) + ";" + "statistics: " + repr(stat))

    sys.exit(0 if ret is True else 255)

#FakeSniff6 - by Leo Liu
