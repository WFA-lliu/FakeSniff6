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

if __name__ == "__main__":
    my_parser = argparse.ArgumentParser(description="CLI argument parsing")
    my_parser.add_argument("-v",
        "--verbose",
        action="store_true",
        help="verbosity")
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
        default="192.168.250.6:9999",
        type=str,
        help="interpreted handle")
    my_parser.add_argument("-o",
        "--oriented",
        metavar="oriented",
        default="",
        type=str,
        help="oriented IP")

    args = my_parser.parse_args()

    if(args.verbose == True):
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.ERROR)
    logging.debug("args: " + repr(args))

    ret = True
    handle_invoke = None
    if len(args.interpreted.split(":")) >= 2:
        handle_invoke = args.oriented + ":" + args.interpreted.split(":")[1]
    fc = FakeCall()
    (ret, stat) = fc.interpret(dir = args.directory, fn = args.filename, handle = args.interpreted, handle_invoke = handle_invoke)
    print("state: " + repr(ret) + ";" + "statistics: " + repr(stat))

    sys.exit(0 if ret is True else 255)

#FakeSniff6 - by Leo Liu
