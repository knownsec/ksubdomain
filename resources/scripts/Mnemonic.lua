-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Mnemonic"
type = "api"

function vertical(domain)
    local page, err = request({url=apiurl(domain)})
    if (err ~= nil and err ~= '') then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or resp["responseCode"] ~= 200) then
        return
    end
    local a = {}
    for i, tb in pairs(resp.data) do
        if (tb.rrtype == "a" or tb.rrtype == "aaaa") then
            table.insert(a,tb.query)
        end
    end
    return a
end

function apiurl(domain)
    return "https://api.mnemonic.no/pdns/v3/" .. domain
end
