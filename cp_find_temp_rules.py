#
# find temp rules.py
# version 1.7
#
# Bilay A. / Ivan Deus
# September 2019, January-February 2020
#

# A package for reading passwords without displaying them on the console.
from __future__ import print_function

import argparse
import getpass
import sys, os
import logging
import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs

def check_key(dict, key):
	# check empty values
	if key in dict:
		return dict[key]
	else:
		return "Not present"

def in_search_for_time_priznak(time_arry, time_obj_name):
    # find time priznak in time array by time name
    for time_arryX in time_arry:
        if time_arryX[2] == time_obj_name :
            return time_arryX[1]

def where_time_used(api_client, time_obj_uid, time_obj_name):
    """
    This method executes 'where-used' command on a given time and returns the command response on success.
    If the original host is not used by any object, the method returns True.
    In case of an error, the method returns False.
    :param api_client: Api client of the domain
    :param time_obj: original time object fully
    :return: the places the host is used, True if the host is not used, False in case of an error
    """
    where_used = api_client.api_call("where-used", {"uid": time_obj_uid})
    if where_used.success is False:
        print("Failed to get " + time_obj_uid + " data:\n{}".format(where_used.error_message))
        return False

    # if the object is not being referenced there is nothing to do.
    if where_used.data["used-directly"]["total"] == 0:
        logging.error("\t" + time_obj_name + " is not used! -- nothing to do")
        return False
    return where_used

def show_comment_n_time_acc_rule(api_client, rul_uid, lay_name):
    # This method executes 'show-access-rule' command
    show_rule = api_client.api_call("show-access-rule", {"uid": rul_uid, "layer": lay_name})
    if show_rule.success is False:
        print("Failed to get ", rul_uid, " data:\n{}".format(show_rule.error_message))
        return ""
    return show_rule.data["comments"], show_rule.data["time"]
    
def main(argv):
    # check arguments
    parser = argparse.ArgumentParser(description='Find temporary rules in all CP policy packages')
    parser.add_argument('-s', help='Mgmt IP address, required', dest='server')
    parser.add_argument('-u', default='Admin', help='User name, Admin by default', dest='username')
    parser.add_argument('-p', help='Password', dest='password')
    parser.add_argument('-d', type=int, default=31, help='Days before expiration, 31 by default', dest='days_in_future')
    args = parser.parse_args()
    #check required fields
    required = "server"
    if args.__dict__[required] is None:
        parser.error("parameter '%s' required" % required)
    #define vars
    api_server = args.server
    username = args.username
    password = args.password
    days_in_future = args.days_in_future
    #user must enter password if it is not in args
    if not password:
        # getting details from the user
        #api_server = input("Enter Mgmt server IP address: ")
        #username = input("Enter username: ")
        if sys.stdin.isatty():
            password = getpass.getpass("Enter password: ")
        else:
            print("Attention! Your password will be shown on the screen!")
            password = input("Enter password: ")
    
    # * LETS DO IT * define current date
    now = datetime.datetime.now()
    print (" -= Find temporary rules to be expired in", days_in_future, "days =- ")
    print (now.strftime(" Today is: T_%Y%m%d  %H:%M"))
    client_args = APIClientArgs(server=api_server)
    with APIClient(client_args) as client:
        logging.basicConfig(filename='find_temp_rules.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
        logging.warning('Client successfully logged in')
        # create debug file. The debug file will hold all the communication between the python script and
        # Check Point's management server.
        client.debug_file = "api_calls.json"
        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)

        # login to server:
        login_res = client.login(username, password, read_only=True)

        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)

        print("Processing. Please wait...")
		# get all time objects from server
        show_times_res = client.api_query("show-times", "full")
        if show_times_res.success is False:
            print("Failed to get the list of all host objects:".format(show_hosts_res.error_message))
            exit(1)

        print("Time objects:")
        # create temp file and init rule and time array and priznak / 0 past 1 present 10 future
        f = open("Temp-rules.csv","w")
        rule_arry = []
        time_arry = []
        priznak = 0
		# convert and compare time objects 1 by 1
        for time_obj in show_times_res.data:
            touid = time_obj["uid"]
            tstrname = time_obj["name"]
            tstrpsx = (time_obj["end"]["posix"]/1000)
            #nowX = 1580605261 #to test now time put here
            nowX = now.timestamp()
            #find rule by uid 1 month from now by time obj posix end time
            date_after_month = (nowX + days_in_future*24*60*60)
            #Determine Whether original posix time Integer Is Between Two Other Integers, make time array with priznak
            if tstrpsx <= nowX :
                priznak = 0 #past
            if nowX <= tstrpsx <= date_after_month :
                priznak = 1 #present
            if tstrpsx >= date_after_month :
                priznak = 10 #future
            time_arry.append([touid,priznak,tstrname])

        # cycle time array and check where used priznak = 1 time objects
        for priznakX in time_arry :
            if priznakX[1] == 1 :
                where_used = where_time_used(client, priznakX[0], priznakX[2])
                if where_used is not False: 
                    for rule in where_used.data["used-directly"]["access-control-rules"]:
                        comment = ''
                        if rule["rule"] is not None and rule["layer"] is not None:
                            # find comment and clean from carrige return and semicolum
                            comment_time = show_comment_n_time_acc_rule(client, rule["rule"]["uid"], rule["layer"]["name"])
                            comment = comment_time[0].replace('\n',' ')
                            comment = comment.replace(';',' ')
                            # find how many time objcts in rule and concat them, also sum future priznak
                            time_obj_names = ''
                            priznakY = 0
                            for time_obj_name in comment_time[1]:
                                priznakY+=in_search_for_time_priznak(time_arry,time_obj_name["name"])
                                time_obj_names += time_obj_name["name"] + " "
                            # add time rules to rule array only if multiple time objects are less then future priznak
                            if priznakY <= 10 :
                                rule_arry.append([rule["position"], check_key(rule["rule"],"name"), time_obj_names,comment,rule["package"]["name"]])
                                print(len(rule_arry), "attached")            
        print(" *** ")
        #sort rule array by 1st (0) column
        rule_arry = sorted(rule_arry, key=lambda x: x[0])
        # dump array values to file 1 by 1
        for exstr in rule_arry:
             exstrs = exstr[0] + " ; " + exstr[1] + " ; " + exstr[2] + " ; " + exstr[3] + " ; " + exstr[4]
             print(exstrs)
             f.write(exstrs  + '\n')
       
        # close temp file
        f.close()
        print(" *** ")
        print("Log data saved into find_temp_rules.log in the same directory which script was runned")
        print("Text data saved into TEMP-RULES.CSV in the same directory which script was runned")

if __name__ == "__main__":
    main(sys.argv[1:])