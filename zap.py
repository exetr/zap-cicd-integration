from zapv2 import ZAPv2
import time
import datetime
import argparse
import requests
import json
import os
import sys


# Define Properties
zapHost = "127.0.0.1"
zapPort = "8082"
zapApiKey = ""
target = ""
conf_lvls={}
report = "zap-report.html"


def main(args):
    global zapHost, zapPort, zapApiKey, target, report
    ## Program exit code status
    status = 0

    ## Set properties
    target = args.t
    if args.host:
        zapHost=str(args.host)
    if args.port:
        zapPort=str(args.port)
    if args.api:
        zapApiKey=str(args.api)
    if args.r:
        report=str(args.r)

    ## Create new ZAP session
    sessionID = generateSessionID()
    zap = generateZapSession(sessionID)
    print("[+] OWASP Zed Attack Proxy v{}".format(zap.core.version))

    ## Open target URL
    print("[*] Opening target: {}".format(target))
    zap.urlopen(target)
    time.sleep(2)

    ## Suppress alerts
    suppress_list = list()
    if args.s:
        with open(args.s) as f:
            fdata = json.load(f)
        for x in fdata['instances']:
            suppress_list.append([x['URL'],x['AlertID']])
    alertFilter(zap, suppress_list)

    ## Initiate Spider scan
    print("[*] Spidering target: {}".format(target))
    scanId = zap.spider.scan(target)
    time.sleep(2)
    while(int(zap.spider.status(scanId))<100):
        print("[*] Spider scan progress: {} %".format(zap.spider.status(scanId)))
        time.sleep(3)
    print("[+] Spider scan completed")

    ## Format output to TFS mode
    if args.tfs is True:
        CLIoutput(json.loads(zap.core.jsonreport()))
        status = TFSoutput(args.c, json.loads(zap.core.jsonreport()), zap.core.htmlreport())
    else:
        CLIoutput(json.loads(zap.core.jsonreport()))
        generateReport(report, zap.core.htmlreport())

    ## Set exit code and terminate program
    if status != 0:
        sys.exit(1)
    else:
        sys.exit(0)


# Function to output reports to respective files (Create file output, write encoded data to file)
def generateReport(path, report_data):
    with open(path, mode='wb') as fp:
        report_data=report_data.encode('utf-8')
        fp.write(report_data)
    print("[+] Report generated: {}\\{}".format(os.getcwd(),path))


# Generate sessionID based on date and time (Generate unique token - time)
def generateSessionID():
    sessionID = str(datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
    return sessionID


# Create ZAP client API and new ZAP session (Create ZAP API object, perform API call to generate new session, return ZAP API object)
def generateZapSession(sessionID):
    zap = ZAPv2(proxies={'http': 'http://'+zapHost+':'+zapPort, 'https': 'https://'+zapHost+':'+zapPort}, apikey=zapApiKey)
    zap.core.new_session(sessionID)
    print("[+] ZAP Session {} started".format(sessionID))
    return zap


# Standard output (Iterate through alerts list and print alert name, ID and number of instances)
def CLIoutput(results):
    i = 1
    print("\n==================== OWASP ZAP Spider Scan Summary ====================\n")
    for x in results['site']['alerts']:
        print("#{} {} [Instances = {}, ID = {}]".format(i, x['alert'], x['count'], x['pluginid']))
        for y in x['instances']:
            print("    {}".format(y['uri']))
        print("\n")
        i = i + 1
    print("=======================================================================\n")
    


# TFS formatted summary output (Check ruleset configuration file, match levels of alerts, output TFS warnings or errors, upload html report, return number of failures)
def TFSoutput(config, results, htmlreport):
    
    ## Define properties
    ruleset = {}
    levels = ["WARN", "IGNORE", "FAIL"]
    warn_count=0
    fail_count=0

    ## Process JSON file containing rules and corresponding warning levels
    if config:
        with open(config) as f:
            ruledata = json.load(f)
        for x in ruledata['alerts']:
            if x['level'] in levels:
                ruleset[x['id']]=x['level']
            else:
                ruleset[x['id']]="WARN"

    ## Check raised alerts against configured warning levels, output relevant information about alerts
    for x in results['site']['alerts']:
        if int(x['pluginid']) in ruleset.keys() and ruleset[int(x['pluginid'])] == "WARN":
            print("##vso[task.logissue type=warning][ZAP Spider] {} (ID = {}, Instances = {})".format(x['alert'], x['pluginid'], x['count']))
            warn_count = warn_count + 1
        elif int(x['pluginid']) in ruleset.keys() and ruleset[int(x['pluginid'])] == "FAIL":
            print("##vso[task.logissue type=error][ZAP Spider] {} (ID = {}, Instances = {})".format(x['alert'], x['pluginid'], x['count']))
            fail_count = fail_count + 1
        elif int(x['pluginid']) in ruleset.keys() and ruleset[int(x['pluginid'])] == "IGNORE":
            pass
        else:
            print("##vso[task.logissue type=warning][ZAP Spider] {} (ID = {}, Instances = {})".format(x['alert'], x['pluginid'], x['count']))
            warn_count = warn_count + 1
    
    ## Summary and upload of HTML report
    if (warn_count | fail_count > 0):
        print("##vso[task.complete result=SucceededWithIssues;][ZAP Spider] Check full logs for more details")
    generateReport(report, htmlreport)
    print("##vso[task.uploadfile]{}.\\{}".format(os.getcwd(),report))

    return fail_count


# Filter out false positives
def alertFilter(zap, suppress_list):

    # Add new context to store URLs of false positive alerts
    contextID = zap.context.new_context("suppressions")

    # Populate context with URLs
    for x in suppress_list:
        zap.context.include_in_context("suppressions",x[0])

    # Add URLs and alert IDs to filter
    for y in suppress_list:
        requests.get("http://"+zapHost+":"+zapPort+"/JSON/alertFilter/action/addAlertFilter/?contextId="+contextID+"&ruleId="+y[1]+"&newLevel=-1&url="+y[0])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A Python script to perform operations in OWASP Zed Attack Proxy, designed with Microsoft Team Foundaton Server integration")
    parser.add_argument("-t", help="Target of vulnerability assessment", required=True, type=str)
    parser.add_argument("-c", help="ONLY FOR TFS SUMMARY - Ruleset JSON configuration file (default=all rules enabled)")
    parser.add_argument("-s", help="JSON file containing list of false positives")
    parser.add_argument("-r", help="Name of report to be generated, optional (default=zap-report.html)")
    parser.add_argument("-host", help="Set host of ZAP instance, (default=127.0.0.1)")
    parser.add_argument("-port", help="Set port which ZAP instance is listening on, (default=8082)")
    parser.add_argument("-api", help="Specify API key of ZAP instance, if any, (default=none)")
    parser.add_argument("-tfs", help="TFS mode, output summary of results compliant to TFS", action='store_true')
    args = parser.parse_args()
    main(args)