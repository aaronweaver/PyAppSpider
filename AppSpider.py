import argparse
import os
import PyAppSpider

authOK = False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AppSpider API Client.', prefix_chars='--')

    parser.add_argument('--url', help='AppSpider URL.', default=None)
    parser.add_argument('--username', help='AppSpider username.', default=None)
    parser.add_argument('--password', help='AppSpider password.', default=None)
    parser.add_argument('--admin-username', help='AppSpider admin username. (Used for global admin features)', default=None)
    parser.add_argument('--admin-password', help='AppSpider admin password. (Used for global admin features)', default=None)
    parser.add_argument('--client', help='Client name.', default=None)
    parser.add_argument('--engine-group', help='Engine group for scanning.', default=None)
    parser.add_argument('--proxy', help='Proxy for client to use for requests.', default=None)

    #AppSpider specific Functions
    parser.add_argument('--scans', help='Retrieve the scans status.', default=False, action='store_true')
    parser.add_argument('--configs', help='Retrieves all the scan configurations.', default=False, action='store_true')
    parser.add_argument('--run-scan', help='Runs the scan with the specified scan name.', default=None)
    parser.add_argument('--create-config', help='Creates a scan configuration', default=None, action='store_true')
    parser.add_argument('--create-run', help='Creates a scan configuration', default=None, action='store_true')
    parser.add_argument('--create-engine-group', help='Engine group for a scan configuration', default=None)
    parser.add_argument('--create-name', help='Config name', default=None)
    parser.add_argument('--create-xml', help='XML configuration for scan', default=None)
    parser.add_argument('--create-seed-url', help='Starting URL for scan', default=None)
    parser.add_argument('--create-constraint-url', help='Include url constraint, example: http://www.yoursite.com/*', default=None)
    parser.add_argument('--engines', help='Lists the engines configured in AppSpider Enterprise', default=False, action='store_true')
    parser.add_argument('--engine-groups', help='Lists the engine groups configured in AppSpider Enterprise', default=False, action='store_true')

    arguments = parser.parse_args()

    #Environment by default override if specified in command line args
    url = arguments.url if arguments.url is not None else os.environ.get('APPSPIDER_URL')
    username = arguments.username if arguments.username is not None else os.environ.get('APPSPIDER_USERNAME')
    password = arguments.password if arguments.password is not None else os.environ.get('APPSPIDER_PASSWORD')
    admin_username = arguments.username if arguments.username is not None else os.environ.get('APPSPIDER_ADMIN_USERNAME')
    admin_password = arguments.password if arguments.password is not None else os.environ.get('APPSPIDER_ADMIN_PASSWORD')
    client = arguments.client if arguments.client is not None else os.environ.get('APPSPIDER_CLIENT')
    engine_group = arguments.engine_group if arguments.engine_group is not None else os.environ.get('APPSPIDER_ENGINE_GROUP')
    proxy = arguments.proxy if arguments.proxy is not None else os.environ.get('APPSPIDER_PROXY')

    #Validate all parameters have been supplied for login
    if url == None or username == None or password == None:
        print "Please specify the AppSpider URL, username and password for login.\n"
        quit()

    proxies = None
    if proxy is not None:
        proxies = {
          'http': proxy,
          'https': proxy,
        }

    #Authenticate
    appspider = PyAppSpider.PyAppSpider(url, debug=False, proxies=proxies)
    admin_appspider = PyAppSpider.PyAppSpider(url, debug=False, proxies=proxies)
    authenticated = appspider.authenticate(username, password)

    #If admin credentials are specified
    if admin_username is not None:
        admin_authenticated = admin_appspider.authenticate(admin_username, admin_password)

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
            if scans.is_success():
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

            if configs.is_success():
                for config in configs.json()["Configs"]:
                    print "Config Name: " +  config["Name"]
        #Run a scan
        elif arguments.run_scan is not None:
            scan_status =  appspider.run_scan(configName=arguments.run_scan)
            if scan_status.is_success():
                print "Scan queued. ID is: " + scan_status.json()["Scan"]["Id"]
        #Create a scan config
        elif arguments.create_config is not None:
            #Find the guid fromt the scanner group name
            groupId = None
            groups = admin_appspider.admin_get_all_engine_groups()

            if groups.is_success():
                for groups in groups.json()["EngineGroups"]:
                    if groups["Name"] == arguments.create_engine_group:
                        groupId = groups["Id"]
            if groupId is not None:
                save_config = appspider.save_config(arguments.create_xml, arguments.create_name, groupId, clientId)

                if save_config.is_success():
                    print "Saved succesfully"
                    if arguments.create_run is not None:
                        scan_status =  appspider.run_scan(configName=arguments.create_name)
                        if scan_status.is_success():
                            print "Scan queued. ID is: " + scan_status.json()["Scan"]["Id"]
                else:
                    print "Config did not save, review the message below."
                    print save_config.data_json(pretty=True)
            else:
                print "Group not found. Please verify the group name:"
                print groups.data_json(pretty=True)
        #List Engines configured
        elif arguments.engines:
            if admin_appspider.loginCode == 1:
                print admin_appspider.admin_get_engines().data_json(pretty=True)
            else:
                print "Not authenticated as an administrator."
        #Admin: List Engines Groups configured
        elif arguments.engine_groups:
            if admin_appspider.loginCode == 1:
                groups = admin_appspider.admin_get_all_engine_groups()
                print "Engine Groups configured on AppSpider:"
                if groups.is_success():
                    for groups in groups.json()["EngineGroups"]:
                        print "Group Name: " +  groups["Name"]
