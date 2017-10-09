import json
import requests
import requests.exceptions
import requests.packages.urllib3

#from . import __version__ as version


class PyAppSpider(object):
    """An API wrapper for AppSpider Enterprise."""

    token = None

    def __init__(self, host, api_version='v1', verify_ssl=True, timeout=60, proxies=None, user_agent=None, cert=None, debug=False):
        """Initialize a AppSpider Enterprise API instance.

        :param host: The URL for the AppSpider Enterprise server. (e.g., http://localhost:8000/AppSpider Enterprise/)
        :param api_key: The API key generated on the AppSpider Enterprise API key page.
        :param user: The user associated with the API key.
        :param api_version: API version to call, the default is v1.
        :param verify_ssl: Specify if API requests will verify the host's SSL certificate, defaults to true.
        :param timeout: HTTP timeout in seconds, default is 30.
        :param proxis: Proxy for API requests.
        :param user_agent: HTTP user agent string, default is "AppSpider Enterprise_api/[version]".
        :param cert: You can also specify a local cert to use as client side certificate, as a single file (containing
        the private key and the certificate) or as a tuple of both file's path
        :param debug: Prints requests and responses, useful for debugging.

        """
        version = ".1"
        self.host = host + 'AppSpiderEnterprise/rest/' + api_version + '/'
        self.api_version = api_version
        self.verify_ssl = verify_ssl
        self.proxies = proxies
        self.timeout = timeout

        if not user_agent:
            self.user_agent = 'pyAppSpider_api/' + version
        else:
            self.user_agent = user_agent

        self.cert = cert
        self.debug = debug  # Prints request and response information.

        token = None
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()  # Disabling SSL warning messages if verification is disabled.

    def authenticate(self, name, password):
        """Returns the AppSpider authentication token.

        :param name: Userid of the appspider user
        :param name: Password of the appspider user

        """

        data = {
            'name': name,
            'password': password
            }

        response = self._request('POST', 'Authentication/Login', data=data)
        self.token = response.data["Token"]

        return response

    ###### Helper Functions ######
    def get_engagement_uri(self, engagement_id):
        """Returns the AppSpider Enterprise API URI for an engagement.

        :param engagement_id: Id of the engagement

        """
        return "/api/" + self.api_version + "/engagements/" + str(engagement_id) + "/"

    def get_product_uri(self, product_id):
        """Returns the AppSpider Enterprise API URI for a product.

        :param product_id: Id of the product

        """
        return "/api/" + self.api_version + "/products/" + str(product_id) + "/"

    def get_test_uri(self, test_id):
        """Returns the AppSpider Enterprise API URI for a test.

        :param test_id: Id of the test

        """
        return "/api/" + self.api_version + "/tests/" + str(test_id) + "/"

    def version_url(self):
        """Returns the AppSpider Enterprise API version.

        """
        return self.api_version

    def get_id_from_url(self, url):
        """Returns the ID from the AppSpider Enterprise API.

        :param url: URL returned by the API

        """
        url = url.split('/')
        return url[len(url)-2]


    ###### Scan API #######
    def get_scans(self):
        """Retrieves the list of scans.

        """

        return self._request('GET', "Scan/GetScans")

    def run_scan(self, configId=None, configName=None):
        """Starts a scan. At least one parameter should be provided to start a scan

        :param configId: Scan config ID (guid)
        :param configName: Scan config name

        """
        params  = {}
        if configId:
            params['configId'] = configId

        if username:
            params['configName'] = configName

        return self._request('POST', "Scan/GetScans/")

    def cancel_scan(self, scanId):
        """Cancels "Starting" or "Waiting for Cloud" scan

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('POST', "/Scan/CancelScan")

    def pause_scan(self, scanId):
        """Pauses a running scan

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('POST', "/Scan/PauseScan")

    def pause_all_scans(self):
        """Pauses all running scans


        """

        return self._request('POST', "/Scan/PauseAllScans")

    def resume_scan(self, scanId):
        """Resumes a scan

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('POST', "/Scan/ResumeScan")

    def resume_all_scans(self):
        """Resumes all scans


        """

        return self._request('POST', "/Scan/ResumeAllScans")

    def stop_scan(self, scanId):
        """Stops a running scan

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('POST', "/Scan/StopScan")

    def stop_all_scans(self):
        """Stops all scans


        """

        return self._request('POST', "/Scan/StopAllScans")

    def get_scan_status(self):
        """Retrieves the scan status represented by a string

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('GET', "Scan/GetScanStatus")

    def is_scan_active(self):
        """Checks to see if the specified scan is active

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('GET', "Scan/IsScanActive")

    def is_scan_finished(self):
        """Checks to see if the specified scan is finished

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('GET', "Scan/IsScanFinished")

    def scan_has_report(self):
        """Checks to see if the specified scan has a report

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('GET', "Scan/HasReport")

    ###### Finding API #######
    def get_vulnerabilities(self):
        """Retrieves the list of vulnerabilities filtered by the specified parameters.

        """

        return self._request('GET', "Finding/GetVulnerabilities")

    ###### Scan Engine Operations #######
    def get_engines(self):
        """Retrieves the list of scan engines.

        """

        return self._request('GET', "Engine/GetEngines")

    def save_engine(self, url, virtualName, login, password, id=None, notes=None, doNotUpdate=None):
        """Creates or updates scan engine

        :param id: if id not provided new engine will be created. if id provided engine update performed.
        :param url: Scan engine URL. URL scheme should be {scheme}://{domain}/{path}/default.asmx
        :param virtualName: Scan engine name
        :param login: Scan engine username
        :param notes: Notes
        :param doNotUpdate: Do not update engine property

        """

        params  = {}

        params['url'] = url
        params['virtualName'] = virtualName
        params['login'] = login
        params['password'] = password

        if id:
            params['id'] = id

        if notes:
            params['notes'] = notes

        if doNotUpdate:
            params['doNotUpdate'] = doNotUpdate

        return self._request('POST', "Engine/SaveEngine")

    def delete_engine(self, ids):
        """Scan engine IDs

        :param ids: Scan Engine ID (guid)

        """

        return self._request('POST', "Engine/DeleteEngine")

    ###### Scan Engine Operations #######
    def get_all_engine_groups(self):
        """Retrieves the list of scan engine groups. Note that System Administrator credentials are required to work with scan engines

        """

        return self._request('GET', "EngineGroup/GetAllEngineGroups")

    def get_engine_groups_for_client(self):
        """Retrieves the list of scan engine groups for a client. Note that System Administrator credentials are required to work with scan engines

        """

        return self._request('GET', "EngineGroup/GetEngineGroupsForClient")

    def save_engine_group(self, name, description=None, monitoring=None, id=None):
        """Creates or updates a scan engine group

        :param id: If id not provided a new engine group will be created. If an id is provided then an engine group update is performed.
        :param name: Scan engine group name. Name should be unique
        :param description: Scan engine group description
        :param monitoring: Scan engine group is monitoring

        """

        params  = {}

        params['name'] = name

        if id:
            params['id'] = id

        if description:
            params['description'] = description

        if monitoring:
            params['monitoring'] = monitoring

        return self._request('POST', "EngineGroup/SaveEngineGroup")

    def delete_engine_group(self, ids):
        """Deletes a scan engine group

        :param ids: Scan engine group IDs (guid)

        """

        params  = {}

        params['ids'] = ids

        return self._request('POST', "EngineGroup/DeleteEngineGroup")

    def delete_engine_group(self, ids):
        """Deletes a scan engine group

        :param ids: Scan engine group IDs (guid)

        """

        params  = {}

        params['ids'] = ids

        return self._request('POST', "EngineGroup/DeleteEngineGroup")

    def add_engine_to_group(self, groupId, engineId):
        """Adds a scan engine to a scan engine group

        :param groupId: Scan engine group ID
        :param engineId: Scan engine ID

        """

        params  = {}

        params['groupId'] = groupId
        params['engineId'] = engineId

        return self._request('POST', "EngineGroup/AddEngineToGroup")

    def delete_engine_from_group(self, groupId, engineId):
        """Deletes scan engine from scan engine group

        :param groupId: Scan engine group ID
        :param engineId: Scan engine ID

        """

        params  = {}

        params['groupId'] = groupId
        params['engineId'] = engineId

        return self._request('POST', "EngineGroup/DeleteEngineFromGroup")

    ###### Report Management #######
    def import_standard_report(self, reportData, scanId=None, configId=None):
        """Creates a new scan in the scan history or updates the report for the specified scan

        :param scanId: Update scan report if scanId provided and create new scan details if not
        :param reportData: Report file
        :param configId: Config id uploaded report attached to

        """

        params  = {}

        params['reportData'] = reportData

        if scanId:
            params['scanId'] = scanId

        if configId:
            params['configId'] = configId

        return self._request('POST', "Report/ImportStandardReport")

    def import_checkmarx_report(self, scanId, file):
        """Creates a new scan in the scan history or updates the report for the specified scan

        :param scanId: Scan ID
        :param file: Checkmarx report XML file

        """

        params  = {}

        params['scanId'] = scanId
        params['file'] = file

        return self._request('POST', "Report/ImportCheckmarxReport")

    def import_checkmarx_report(self, scanId):
        """Gets VulnerabilitiesSummary.xml for the scan. Only scans in "Completed" and "Stopped" states may have a report

        :param scanId: Scan ID

        """

        params  = {}

        params['scanId'] = scanId

        return self._request('GET', "Report/GetVulnerabilitiesSummaryXml")

    def import_checkmarx_report(self, scanId):
        """Gets VulnerabilitiesSummary.xml for the scan. Only scans in "Completed" and "Stopped" states may have a report

        :param scanId: Scan ID

        """

        params  = {}

        params['scanId'] = scanId

        return self._request('GET', "Report/GetCrawledLinksXml")

    ###### Scan Configuration Operations #######
    def import_standard_report(self, xml, name, engineGroupId, id=None, defendEnabled=None, monitoring=None, monitoringDelay=None, monitoringTriggerScan=None, isApproveRequired=None):
        """Creates a new scan configuration

        :param id: If id not provided new config will be created. If id provided config update performed.
        :param xml: Scan config xml file. Config name should be unique in the client.
        :param defendEnabled: AppSpider Defend enabled
        :param monitoring: Monitoring scanning enabled
        :param monitoringDelay: Delay between monitoring scans in hours. Possible values are 1 (hour), 24 (day), 168 (week), 720 (month)
        :param monitoringTriggerScan: Monitoring scan triggers attack scan if changes found
        :param name: Config name
        :param engineGroupId: Engine group id for scan config
        :param isApproveRequired: Approve required property

        """

        params  = {}

        params['xml'] = xml
        params['name'] = name
        params['engineGroupId'] = engineGroupId

        if id:
            params['id'] = id

        if defendEnabled:
            params['defendEnabled'] = defendEnabled

        if monitoring:
            params['monitoring'] = monitoring

        if monitoringDelay:
            params['monitoringDelay'] = monitoringDelay

        if monitoringTriggerScan:
            params['monitoringTriggerScan'] = monitoringDelay

        if isApproveRequired:
            params['isApproveRequired'] = monitoring

        return self._request('POST', "Config/SaveConfig")

    def get_config(self, id):
        """Retrieves scan config for the client

        :param id: Scan config ID

        """

        params  = {}

        params['id'] = id

        return self._request('POST', "Config/GetConfig")

    def get_attachment(self, configId, fileName, fileType):
        """Retrieves auxiliary files (such as macro, traffic recording, etc), referenced in the scan configuration

        :param configId: Scan config ID
        :param fileName: Name of requested file
        :param fileType: File type. Values are: "Authentication", "Certificate", "Crawling", "Selenium", "Traffic", "Wsdl

        """

        params  = {}

        params['configId'] = configId
        params['fileName'] = fileName
        params['fileType'] = fileType

        return self._request('POST', "Config/GetAttachment")

    def get_attachments(self, configId):
        """Retrieves auxiliary files (such as macro, traffic recording, etc), referenced in the scan configuration

        :param configId: Scan config ID

        """

        params  = {}

        params['configId'] = configId


        return self._request('POST', "Config/GetAttachments")


    # Utility
    @staticmethod
    def _build_list_params(param_name, key, values):
        """Builds a list of POST parameters from a list or single value."""
        params = {}
        if hasattr(values, '__iter__'):
            index = 0
            for value in values:
                params[str(param_name) + '[' + str(index) + '].' + str(key)] = str(value)
                index += 1
        else:
            params[str(param_name) + '[0].' + str(key)] = str(values)
        return params

    def _request(self, method, url, params=None, data=None, files=None):
        """Common handler for all HTTP requests."""
        if not params:
            params = {}

        if data:
            data = json.dumps(data)

        headers = {
            'User-Agent': self.user_agent,
            'Authorization': 'Basic ' + str(self.token)
        }

        if not files:
            headers['Accept'] = 'application/json'
            headers['Content-Type'] = 'application/json'

        if self.proxies:
            proxies=self.proxies
        else:
            proxies = {}

        try:
            if self.debug:
                print(method + ' ' + url)
                print(params)

            response = requests.request(method=method, url=self.host + url, params=params, data=data, files=files, headers=headers,
                                        timeout=self.timeout, verify=self.verify_ssl, cert=self.cert, proxies=proxies)

            if self.debug:
                print(response.status_code)
                print(response.text)

            try:
                if response.status_code == 201: #Created new object
                    object_id = response.headers["Location"].split('/')
                    key_id = object_id[-2]
                    try:
                        data = int(key_id)
                    except:
                        data = response.json()

                    return AppSpiderResponse(message="Upload complete", data=data, success=True)
                elif response.status_code == 204: #Object updates
                    return AppSpiderResponse(message="Object updated.", success=True)
                elif response.status_code == 404: #Object not created
                    return AppSpiderResponse(message="Object id does not exist.", success=False)
                else:
                    data = response.json()
                    return AppSpiderResponse(message="Success", data=data, success=True, response_code=response.status_code)
            except ValueError:
                return AppSpiderResponse(message='JSON response could not be decoded.', success=False)
        except requests.exceptions.SSLError:
            return AppSpiderResponse(message='An SSL error occurred.', success=False)
        except requests.exceptions.ConnectionError:
            return AppSpiderResponse(message='A connection error occurred.', success=False)
        except requests.exceptions.Timeout:
            return AppSpiderResponse(message='The request timed out after ' + str(self.timeout) + ' seconds.',
                                     success=False)
        except requests.exceptions.RequestException:
            return AppSpiderResponse(message='There was an error while handling the request.', success=False)


class AppSpiderResponse(object):
    """
    Container for all AppSpider Enterprise API responses, even errors.

    """

    def __init__(self, message, success, data=None, response_code=-1):
        self.message = message
        self.data = data
        self.success = success
        self.response_code = response_code

    def __str__(self):
        if self.data:
            return str(self.data)
        else:
            return self.message

    def json(self):
        return self.data

    def id(self):
        if self.response_code == 400: #Bad Request
            raise ValueError('Object not created:' + json.dumps(self.data, sort_keys=True, indent=4, separators=(',', ': ')))
        return int(self.data)

    def count(self):
        return self.data["TotalCount"]

    def is_success(self):
        return self.data["IsSuccess"]

    def error(self):
        return self.data["ErrorMessage"]

    def data_json(self, pretty=False):
        """Returns the data as a valid JSON string."""
        if pretty:
            return json.dumps(self.data, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            return json.dumps(self.data)
