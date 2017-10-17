import argparse
import os
import PyAppSpider

authOK = False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AppSpider API Client.', prefix_chars='--')

    parser.add_argument('--url', help='AppSpider URL.', default=None)
    parser.add_argument('--username', help='AppSpider URL.', default=None)
    parser.add_argument('--password', help='AppSpider URL.', default=None)
    parser.add_argument('--client', help='Client name.', default=None)
    parser.add_argument('--engine-group', help='Engine group for scanning.', default=None)

    #AppSpider specific Functions
    parser.add_argument('--scans', help='Retrieve the scans status.', default=False, action='store_true')
    parser.add_argument('--configs', help='Retrieves all the scan configurations.', default=False, action='store_true')

    arguments = parser.parse_args()

    #Environment by default override if specified in command line args
    url = arguments.url if arguments.url is not None else os.environ.get('APPSPIDER_URL')
    username = arguments.username if arguments.username is not None else os.environ.get('APPSPIDER_USERNAME')
    password = arguments.password if arguments.password is not None else os.environ.get('APPSPIDER_PASSWORD')
    client = arguments.client if arguments.client is not None else os.environ.get('APPSPIDER_CLIENT')
    engine_group = arguments.engine_group if arguments.engine_group is not None else os.environ.get('APPSPIDER_ENGINE_GROUP')

    #Validate all parameters have been supplied for login
    if url == None or username == None or password == None:
        print "Please specify the AppSpider URL, username and password for login.\n"
        quit()

    proxies = {
      'http': 'http://localhost:8081',
      'https': 'http://localhost:8081',
    }

    #Authenticate
    appspider = PyAppSpider.PyAppSpider(url, debug=False, proxies=proxies)
    authenticated = appspider.authenticate(username, password)

    if appspider.loginCode == 1: #Single client
        authOK = True
    elif appspider.loginCode == 2 and client is None: #Multi client
        print "The following clients are available to this user:"

        for spiderClient in appspider.clients:
            print spiderClient

        print "\nRe-run the utility with the --client parameter use one of the client name specified in the list above. Alternatively set the APPSPIDER_CLIENT environment variable.\n"
    elif appspider.loginCode == 2 and client is not None: #Multi client specified
        #Authenticate and find the client guid
        authenticated = appspider.authenticate(username, password)
        clientId = None
        for spiderClient in appspider.clients:
            if client == spiderClient:
                clientId = appspider.clients[client]
        if clientId is not None:
            authenticated = appspider.authenticate(username, password, clientId)

            if appspider.loginCode == 1:
                authOk = True
        else:
            print "Invalid Client Name"
    else:
        print "Authentication problem: " + authenticated.error()

    #Authenticated, let's do something fun
    if authOk == True:

        #Retrieve the scans and status
        if arguments.scans:
            scans =  appspider.get_scans()
            print "Scan status for client: " + client
            if scans.is_success:
                for scan in scans.json()["Scans"]:
                    print "Status: " +  appspider.get_scan_status_text(scan["Status"])
                    for target in scan["Targets"]:
                        print "URL: " + target["Host"]
                    print "Started: " + scan["StartTime"]

                    if scan["CompletionTime"] is not None:
                        print "Completed: " + scan["CompletionTime"]
                    else:
                        print "Not Completed"
                    print
            else:
                print "No scans found"

        #Get the current configurations
        elif arguments.configs:
                configs =  appspider.get_configs()
                print "Configurations for client: " + client

                if configs.is_success:
                    for config in configs.json()["Configs"]:
                        print "Config Name: " +  config["Name"]
