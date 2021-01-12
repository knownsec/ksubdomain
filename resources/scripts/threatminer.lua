-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ThreatMiner"
type = "api"

function vertical(domain)
    local page, err = request({
        url=buildurl(domain),
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or resp['status_code'] ~= "200" or resp['status_message'] ~= "Results found." or #(resp.results) == 0) then
        return
    end
    local a = {}
    for i, sub in pairs(resp.results) do
        table.insert(a,sub)
    end
    return a
end

function buildurl(domain)
    return "https://api.threatminer.org/v2/domain.php?q=" .. domain .. "&api=True&rt=5"
end

