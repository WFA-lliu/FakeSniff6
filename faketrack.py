#! python3
import os
import sys
import argparse
import logging
import re
import codecs
import shlex
import subprocess
from datetime import datetime

class FakeTrack():
    @staticmethod
    def find_folder(dir: str = ".") -> list:
        folder = list()
        for root, dirs, files in os.walk(dir):
            if len(dirs) == 0:
                folder.append(root)
        return folder

    @staticmethod
    def get_dt(ts: str = None) -> datetime:
        ts = ts.replace("T", " ")
        ts = ts.replace("_", ":")
        ts = ts.rstrip("Z")
        fmt: str = "%Y-%m-%d %H:%M:%S"
        dt: datetime = None
        try:
            dt = datetime.strptime(ts, fmt)
        except:
            pass
        return dt

    @staticmethod
    def get_ts(dt: datetime = None) -> str:
        ts = ("%04d-%02d-%02dT%02d_%02d_%02dZ" % (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second))
        return ts

    @staticmethod
    def get_directory(ver: str = None, type: str = None, name: str = None, dt: datetime = None) -> str:
        delimiter: str = "_"
        dir: str = ver + delimiter + type + delimiter + name + delimiter + FakeTrack.get_ts(dt)
        return dir

    @staticmethod
    def get_report(dir: list = None) -> tuple:
        fldr: list = ["PASS", "FAIL", "INCOMPLETE", "NOT_TESTED"]
        raw: dict = dict()
        aux: dict = dict()
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
                aux[f] = dict()
                for d in subdir:
                    logging.debug("d: " + os.path.basename(d))
                    patt: list = os.path.basename(d).split(delimiter)
                    name = delimiter.join(patt[2:len(patt)-3])
                    if len(name) == 0:
                        continue
                    raw[f].add(name)
                    ts = delimiter.join(patt[len(patt)-3:])
                    dt = FakeTrack.get_dt(ts)
                    if name not in aux:
                        aux[f][name]: dict = dict()
                        aux[f][name]["ver"] = patt[0]
                        aux[f][name]["type"] = patt[1]
                        aux[f][name]["dt"] = dt
                    else:
                        updated: bool = (dt > aux[f][name]["dt"])
                        logging.debug("f: " + f + "; " + "name: " + name + "; " + "dt (prev): " + str(aux[f][name]["dt"]) + ", " + "dt (next): " + str(dt) + "; " + "updated: " + str(updated))
                        if dt > aux[f][name]["dt"]:
                            aux[f][name]["dt"] = dt
        p = None
        if "PASS" in raw:
            p = raw["PASS"]
        diff_f_p = None
        if "FAIL" in raw and "PASS" in raw:
            diff_f_p = raw["FAIL"] - raw["PASS"]
        diff_i_f_p = None
        if "INCOMPLETE" in raw and "FAIL" in raw and "PASS" in raw:
            diff_i_f_p = raw["INCOMPLETE"] - raw["FAIL"] - raw["PASS"]
        diff_n_i_f_p = None
        if "NOT_TESTED" in raw and "INCOMPLETE" in raw and "FAIL" in raw and "PASS" in raw:
            diff_n_i_f_p = raw["NOT_TESTED"] - raw["INCOMPLETE"] - raw["FAIL"] - raw["PASS"]
        rpt: dict = dict()
        rpt["PASS"] = p
        rpt["REMAIN_FAIL"] = diff_f_p
        rpt["REMAIN_INCOMPLETE"] = diff_i_f_p
        rpt["REMAIN_NOT_TESTED"] = diff_n_i_f_p
        #rpt: unique name above categories
        #aux: latest meta-data for each category
        return (rpt, aux)

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
        help="directory of QTT Test-Logs")
    my_parser.add_argument("-p",
        "--persistent",
        metavar="persistent",
        default=None,
        type=str,
        help="directory of QTT Test-Logs for persistent")
    my_parser.add_argument("-m",
        "--mode",
        metavar="mode",
        default="view",
        choices=["view", "backup"],
        type=str,
        help="mode for test log manipulation")
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

    (rpt, aux) = FakeTrack.get_report(dir = args.directory)
    logging.debug("rpt: " + repr(rpt))
    logging.debug("aux: " + repr(aux))
    ret: bool = False
    if args.mode == "view":
        if rpt is not None:
            cnt: int = 0
            for outer in rpt:
                l: list = list()
                if rpt[outer] is not None:
                    l = sorted(rpt[outer])
                if args.category == "all" or args.category == outer.lower():
                    print("category: %s; quantity: %d" % (outer, len(l)))
                for inner in l:
                    if args.category == "all" or args.category == outer.lower():
                        print("%s%s" % ("    ", inner))
                    cnt += 1
            print("total: %d" % (cnt))
            ret = True
    elif args.mode == "backup":
        logging.debug(os.path.abspath(os.getcwd()))
        logging.debug(os.path.abspath(args.persistent))
        if os.path.abspath(os.getcwd()) != os.path.abspath(args.persistent):
            if args.persistent is not None and rpt is not None and aux is not None:
                s: str = args.directory
                if not s.endswith(os.path.sep):
                    s += os.path.sep
                d: str = args.persistent
                if not d.endswith(os.path.sep):
                    d += os.path.sep
                if os.path.exists(d) is False:
                    os.makedirs(d, mode = 0o777, exist_ok = True)
                avail: bool = True
                cnt: int = 0
                for outer in aux:
                    os.makedirs(d + outer, mode = 0o777, exist_ok = True)
                    for inner in aux[outer]:
                        c: str = FakeTrack.get_directory(aux[outer][inner]["ver"], aux[outer][inner]["type"], inner, aux[outer][inner]["dt"])
                        logging.debug("c: " + c)
                        srcdir: str = s + outer + os.path.sep + c
                        dstdir: str = d + outer + os.path.sep + c
                        s_exist: bool = os.path.exists(srcdir)
                        logging.debug("s_exist: {}; srcdir: {}".format(s_exist, srcdir))
                        if s_exist is False:
                            avail = False
                            break
                        d_return: int = subprocess.call(["cp", "-r", srcdir, os.path.dirname(dstdir)], shell=False)
                        logging.debug("d_return: {}; dstdir: {}".format(d_return, dstdir))
                        if d_return != 0:
                            avail = False
                            break
                        cnt += 1
                print("total: %d" % (cnt))
                ret = True if avail is True else False
    else:
        pass

    sys.exit(0 if ret is True else 255)

#FakeSniff6 - by Leo Liu
