import PyAppSpider

proxies = {
  'http': 'http://localhost:8080',
  'https': 'http://localhost:8080',
}

spider = PyAppSpider.PyAppSpider("http://pvw-spiderent01/", debug=False, proxies=proxies)

spider.authenticate("admin-user", "secret")
print spider.get_all_engine_groups().data_json(pretty=True)
print spider.get_engines().data_json(pretty=True)

spider.authenticate("client_user", "secret")
results =  spider.get_scans()
print results.data_json(pretty=True)
print results.is_success()
print spider.get_vulnerabilities().data_json(pretty=True)
