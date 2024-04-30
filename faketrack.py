#! python3
import os
import sys
import argparse
import logging
import re
import codecs

class FakeTrack():
    @staticmethod
    def find_folder(dir: str = ".") -> list:
        folder = list()
        for root, dirs, files in os.walk(dir):
            if len(dirs) == 0:
                folder.append(root)
        return folder

    @staticmethod
    def get_report(dir: list = None) -> dict:
        fldr: list = ["PASS", "FAIL", "INCOMPLETE", "NOT_TESTED"]
        raw: dict = dict()
        delimiter: str = "_"
        for f in fldr:
            subfldr: str = dir
            if not subfldr.endswith(os.path.sep):
                subfldr += os.path.sep
            subfldr += f
            if os.path.isdir(subfldr):
                logging.debug("subfldr: " + subfldr)
                subdir: list = FakeTrack.find_folder(subfldr)
                raw[f] = set()
                for d in subdir:
                    logging.debug("d: " + os.path.basename(d))
                    patt: list = os.path.basename(d).split(delimiter)
                    name = delimiter.join(patt[2:len(patt)-3])
                    raw[f].add(name)
        #logging.debug("raw: " + repr(raw))
        diff_f_p = raw["FAIL"] - raw["PASS"]
        diff_i_p_f = raw["INCOMPLETE"] - raw["PASS"] - raw["FAIL"]
        diff_n_i_p_f = raw["NOT_TESTED"] - raw["INCOMPLETE"] - raw["PASS"] - raw["FAIL"]
        rpt: dict = dict()
        rpt["PASS"] = raw["PASS"]
        rpt["REMAIN_FAIL"] = diff_f_p
        rpt["REMAIN_INCOMPLETE"] = diff_i_p_f
        rpt["REMAIN_NOT_TESTED"] = diff_n_i_p_f
        return rpt

if __name__ == "__main__":
    my_parser = argparse.ArgumentParser(description="CLI argument parsing")
    my_parser.add_argument("-v",
        "--verbose",
        action="store_true",
        help="verbosity")
    my_parser.add_argument("-d",
        "--directory",
        metavar="directory",
        default="/usr/local/bin/WFA-QuickTrack-Tool/Test-Logs",
        type=str,
        help="directory of UCC log and capture")
    my_parser.add_argument("-y",
        "--category",
        metavar="category",
        default="all",
        choices=["all", "pass", "remain_fail", "remain_incomplete", "remain_not_tested"],
        type=str,
        help="category of report")

    args = my_parser.parse_args()

    if(args.verbose == True):
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.ERROR)
    logging.debug("args: " + repr(args))

    rpt = FakeTrack.get_report(dir = args.directory)
    logging.debug("rpt: " + repr(rpt))
    ret: bool = False
    if rpt is not None:
        cnt: int = 0
        for outer in rpt:
            l: list = sorted(rpt[outer])
            if args.category == "all" or args.category == outer.lower():
                print("category: %s; quantity: %d" % (outer, len(l)))
            for inner in l:
                if args.category == "all" or args.category == outer.lower():
                    print("%s%s" % ("    ", inner))
                cnt += 1
        print("total: %d" % (cnt))
        ret = True

    sys.exit(0 if ret is True else 255)

#FakeSniff6 - by Leo Liu
