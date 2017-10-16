import PyAppSpider

proxies = {
  'http': 'http://localhost:8080',
  'https': 'http://localhost:8080',
}

proxies=proxies
spider = PyAppSpider.PyAppSpider("http://spider-enterprise", debug=True, proxies=proxies)

#Enterprise non-multi client account authentication
result = spider.authenticate("user", "secret")

if result == 1:
    scans = spider.get_scans().data_json(pretty=True)
else:
    print "Authentication problem"

#Enterprise multi client authentication
result = spider.authenticate("user-multi-client", "secret")

if result == 2:
    #Select the client you wish to login as replacing client_name with the client name
    clientName = "client_name"
    spider.clients[clientName]

    #Now re-authenticate with the clientid
    result = spider.authenticate("user-multi-client", "secret", spider.clients[clientName])

    if result == 1:
        results =  spider.get_scans()
        spider.save_config("scan_configs/scan_config.xml", "Scan_Config_Name", spider.clients[clientName], scanner_guid)

    else:
        print "Authentication problem"
